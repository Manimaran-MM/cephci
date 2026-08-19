"""NFS TSM integration (TC-01..TC-10) on one shared cluster."""

import time
from threading import Thread

from cli.utilities.utils import reboot_node
from tests.nfs.lib.common_lib import enable_nfs_debug_logs, get_nfs_container_id, get_node_time
from tests.nfs.lib.tsm import NfsTsmValidation
from tests.nfs.lib.tsm.constants import NfsFcntlLock
from tests.nfs.lib.tsm.helpers import (
    announce,
    check_coredumps,
    kill_holds,
    log_workflow_summary,
    peer_summary,
    start_bg,
    wait_peer_counts,
)
from tests.nfs.lib.tsm.integration import (
    DELEG_MODES,
    active_mds_rank,
    assert_ganesha_id_unchanged,
    assert_mds_sessions_ok,
    mount_three_exports,
    orch_nfs_daemons,
    record_ganesha_id,
    redeploy_nfs_daemon,
    remove_nfs_daemon,
    reapply_nfs_spec,
    resolve_nfs_nodes,
    restart_nfs_daemon,
    setup_three_exports,
    snapshot_mds_sessions,
    teardown_three_exports,
    wait_daemon_running,
    wait_new_container,
    wait_nfs_running_count,
    wait_orch_hosts,
)
from tests.nfs.tsm.test_nfs_tsm_basic import (
    build_spec,
    deploy_step,
    nodes_running_nfs,
    safe_cleanup,
)
from tests.nfs.tsm.test_nfs_tsm_grace_io import GraceCtx, enter_grace
from utility.log import Log

log = Log(__name__)

NFS_NAME = "cephfs-nfs-integ"
TSM_PORT = 36373
NFS_PORT = 12053
MONITORING_PORT = 19587
RECOVERY_TIMEOUT = 120
INTEG_CLIENT_COUNT = 3
DEFAULT_NFS_COUNT = 3
TC10_POOL_EXTRA = 1


def _hold_peer_tsm_delta(deleg_mode):
    """Peer TSM deltas after open+fcntl-lock hold.

    Non-rw exports sync open+lock to peers. On deleg=rw exports the lock stays
    client-local once a write delegation is held; peers see open+deleg instead.
    """
    if deleg_mode == "rw":
        return {"delta_open": 1, "delta_lock": 0, "delta_deleg": 1}
    return {"delta_open": 1, "delta_lock": 1, "delta_deleg": 0}


HOLD_STEPS = tuple(_hold_peer_tsm_delta(m) for m in DELEG_MODES)
HOLD_POLL_SETTLE_SEC = 2
DEPLOY_SETTLE_SEC = 5
FALLBACK_MOUNT = "/mnt/integ_exp0"
FALLBACK_EXPORT = "/export_integ_0"
SUMMARY_TITLE = "TSM INTEGRATION SUMMARY"
SUMMARY_WIDTH = 8


def _teardown_integ(ctx=None, clients=None, pool_nodes=None):
    """Remove exports/mounts and delete the integration NFS cluster."""
    clients = clients or (ctx.clients if ctx else [])
    pool = pool_nodes or (ctx.pool_nodes if ctx else [])
    if not clients or not pool:
        return
    if ctx:
        kill_holds(ctx.holds)
        ctx.holds.clear()
        if ctx.mounts and ctx.exports:
            teardown_three_exports(ctx.cmd, ctx.clients, ctx.mounts, ctx.exports)
    safe_cleanup(
        clients[0],
        ctx.mounts[0] if ctx and ctx.mounts else FALLBACK_MOUNT,
        NFS_NAME,
        ctx.exports[0]["export"] if ctx and ctx.exports else FALLBACK_EXPORT,
        pool,
    )


class IntegCtx:
    def __init__(self, ceph_cluster, installer, clients, pool_nodes, active, nfs_port, nfs_version, config):
        self.ceph_cluster = ceph_cluster
        self.installer = installer
        self.clients = clients
        self.pool_nodes = pool_nodes
        self.nfs_count = int(config.get("nfs_count", DEFAULT_NFS_COUNT))
        self.active = active
        self.server = active[0]
        self.peers = active[1:]
        self.nfs_name = NFS_NAME
        self.nfs_port = nfs_port
        self.nfs_version = nfs_version
        self.config = config
        self.exports = []
        self.mounts = []
        self.holds = []
        self.cmd = clients[0]
        self.hold_since = None
        self.want_tsm = {}
        self.ganesha_id = None
        self.mds_pre = []
        self.disrupt_since = None
        self.all_nfs_nodes = []
        self.validator = NfsTsmValidation(ceph_cluster, clients[0], "enable_TSM", "Tsm_Port", TSM_PORT)


def _refresh_active(ctx):
    active = nodes_running_nfs(ctx.pool_nodes, ctx.nfs_name)
    if active:
        ctx.active = active
        ctx.server = active[0]
        ctx.peers = active[1:]
    return active


def _peer_hosts(ctx):
    return [p.hostname for p in ctx.peers]


def _deploy_fail(reason, clients, pool, ctx=None):
    log.info("%s; cleaning up %s", reason, NFS_NAME)
    _teardown_integ(ctx=ctx, clients=clients, pool_nodes=pool)
    return None


def deploy_shared_cluster(ceph_cluster, installer, clients, nfs_nodes, config):
    nfs_count = int(config.get("nfs_count", DEFAULT_NFS_COUNT))
    if len(nfs_nodes) < nfs_count:
        log.error("Need >=%s NFS nodes (have %s)", nfs_count, len(nfs_nodes))
        return None
    pool = nfs_nodes[:nfs_count]
    step = {
        "nfs_count": nfs_count,
        "nfs_port": NFS_PORT,
        "tsm_port": TSM_PORT,
        "monitoring_port": MONITORING_PORT,
        "placement": config.get("placement", "hosts"),
        "enable_debug": False,
    }
    log.info("Deploy nfs_count=%s hosts=%s", nfs_count, [n.hostname for n in pool])
    result = deploy_step(ceph_cluster, installer, clients[0], pool, step, NFS_NAME, "integ")
    if result is None:
        return _deploy_fail("deploy failed", clients, pool)
    _, active, nfs_port, _ = result

    ctx = IntegCtx(
        ceph_cluster, installer, clients, pool, active, nfs_port,
        str(config.get("nfs_version", "4.2")), config,
    )
    ctx.all_nfs_nodes = list(nfs_nodes)
    ctx.exports = setup_three_exports(clients[0], NFS_NAME)
    if not ctx.exports:
        return _deploy_fail("export setup failed", clients, pool, ctx)
    ctx.mounts = mount_three_exports(clients, ctx.exports, ctx.server, nfs_port, ctx.nfs_version)
    if ctx.mounts is None:
        return _deploy_fail("mount setup failed", clients, pool, ctx)
    enable_nfs_debug_logs(clients[0], NFS_NAME, "TSM")
    _refresh_active(ctx)
    time.sleep(DEPLOY_SETTLE_SEC)
    ctx.ganesha_id = record_ganesha_id(ctx.cmd, ctx.nfs_name)
    return ctx


def _prepare_tc10_placement(ctx):
    """TC-10: 4-host pool, 3 daemons (placement count)."""
    pool_size = ctx.nfs_count + TC10_POOL_EXTRA
    if len(ctx.all_nfs_nodes) < pool_size:
        log.error("TC-10 needs %s NFS nodes (have %s)", pool_size, len(ctx.all_nfs_nodes))
        return False
    pool_nodes = ctx.all_nfs_nodes[:pool_size]
    hosts = [n.hostname for n in pool_nodes]
    spec = build_spec(
        NFS_NAME,
        NFS_PORT,
        TSM_PORT,
        True,
        ctx.nfs_count,
        hosts,
        "count",
        monitoring_port=MONITORING_PORT,
    )
    if not spec or not reapply_nfs_spec(ctx.installer, spec, pool_nodes):
        return False
    if not wait_nfs_running_count(ctx.cmd, ctx.nfs_name, ctx.nfs_count):
        return False
    ctx.pool_nodes = pool_nodes
    _refresh_active(ctx)
    ctx.ganesha_id = record_ganesha_id(ctx.cmd, ctx.nfs_name)
    return True


def _start_one_hold(ctx, index):
    client = ctx.clients[index]
    mnt = ctx.mounts[index]
    hold_f = f"{mnt}/tc_hold_{index}.txt"
    if DELEG_MODES[index] is None:
        client.exec_command(
            sudo=True, cmd=f"bash -c 'touch {hold_f}; chmod 666 {hold_f}'", check_ec=False,
        )
    pid = start_bg(client, NfsFcntlLock.exclusive_hold(hold_f))
    return (client, pid) if pid else None


def setup_suite_holds(ctx):
    """Start all holds once after deploy."""
    _refresh_active(ctx)
    ctx.hold_since, _ = get_node_time(ctx.peers)
    cur_o = cur_l = cur_d = 0
    for i, step in enumerate(HOLD_STEPS):
        hold = _start_one_hold(ctx, i)
        if not hold:
            raise RuntimeError(f"failed to start hold {i}")
        ctx.holds.append(hold)
        time.sleep(HOLD_POLL_SETTLE_SEC)
        cur_o += step["delta_open"]
        cur_l += step["delta_lock"]
        cur_d += step["delta_deleg"]
        if wait_peer_counts(
            ctx.peers, ctx.nfs_name, ctx.hold_since,
            cur_o, cur_l, f"setup:hold{i}", expect_deleg=cur_d,
        ) is None:
            raise RuntimeError(f"setup hold {i} peer TSM timeout")
    ctx.want_tsm = {"open": cur_o, "lock": cur_l, "deleg": cur_d}


def pre_workflow(ctx, tag):
    _refresh_active(ctx)
    ctx.mds_pre = snapshot_mds_sessions(ctx.cmd, f"{tag}:pre")
    ctx.ganesha_id = record_ganesha_id(ctx.cmd, ctx.nfs_name)
    w = ctx.want_tsm
    if wait_peer_counts(
        ctx.peers, ctx.nfs_name, ctx.hold_since,
        w["open"], w["lock"], f"{tag}:pre",
        expect_deleg=w.get("deleg", 0), timeout=RECOVERY_TIMEOUT,
    ) is None:
        raise RuntimeError(f"[{tag}] pre-workflow peer TSM not at baseline")


def post_workflow(ctx, tag):
    _refresh_active(ctx)
    w = ctx.want_tsm
    log_since = ctx.disrupt_since or ctx.hold_since
    if wait_peer_counts(
        ctx.peers, ctx.nfs_name, log_since,
        w["open"], w["lock"], f"{tag}:post",
        expect_deleg=w.get("deleg", 0), timeout=RECOVERY_TIMEOUT,
    ) is None:
        return 1
    if assert_ganesha_id_unchanged(ctx.ganesha_id, record_ganesha_id(ctx.cmd, ctx.nfs_name), tag):
        return 1
    if assert_mds_sessions_ok(ctx.mds_pre, snapshot_mds_sessions(ctx.cmd, f"{tag}:post"), tag):
        return 1
    if ctx.validator.assert_tsm_ready(
        ctx.nfs_name, ctx.active, tsm_port=TSM_PORT, timeout=120,
        log_since=ctx.disrupt_since, check_boot_logs=False,
    ):
        return 1
    return 0


def _for_hosts(ctx, hostnames, fn):
    for host in hostnames:
        if not fn(ctx.cmd, ctx.nfs_name, host):
            return 1
    return 0


def _primary_daemon(ctx, fn):
    ctx.disrupt_since, _ = get_node_time(ctx.active)
    return 0 if fn(ctx.cmd, ctx.nfs_name, ctx.server.hostname) else 1


def tc_01_daemon_rm_primary(ctx, tag):
    host = ctx.server.hostname
    old_cid = get_nfs_container_id(ctx.server, nfs_name=ctx.nfs_name)
    ctx.disrupt_since, _ = get_node_time(ctx.active)
    remove_nfs_daemon(ctx.cmd, ctx.nfs_name, host)
    post = peer_summary(ctx.peers, ctx.nfs_name, since=ctx.disrupt_since)
    w = ctx.want_tsm
    if (
        not post.get("seen")
        or post["open"] < w["open"]
        or post["lock"] < w["lock"]
        or post.get("deleg", 0) < w.get("deleg", 0)
    ):
        log.error("[%s] mid-rm TSM want %s got %s", tag, w, post)
        return 1
    if not wait_daemon_running(ctx.cmd, ctx.nfs_name, host):
        return 1
    if old_cid:
        wait_new_container(ctx.server, ctx.nfs_name, old_cid)
    return 0


def tc_02_daemon_restart_primary(ctx, tag):
    return _primary_daemon(ctx, restart_nfs_daemon)


def tc_03_daemon_redeploy_primary(ctx, tag):
    return _primary_daemon(ctx, redeploy_nfs_daemon)


def tc_04_daemon_rm_peers(ctx, tag):
    peers = _peer_hosts(ctx)
    ctx.disrupt_since, _ = get_node_time(ctx.active)
    for host in peers:
        remove_nfs_daemon(ctx.cmd, ctx.nfs_name, host)
    return 0 if wait_orch_hosts(ctx.cmd, ctx.nfs_name, peers) else 1


def tc_05_daemon_restart_peers(ctx, tag):
    ctx.disrupt_since, _ = get_node_time(ctx.active)
    return _for_hosts(ctx, _peer_hosts(ctx), restart_nfs_daemon)


def tc_06_daemon_redeploy_peers(ctx, tag):
    ctx.disrupt_since, _ = get_node_time(ctx.active)
    return _for_hosts(ctx, _peer_hosts(ctx), redeploy_nfs_daemon)


def _mds_fail_later(cmd_host, delay):
    time.sleep(delay)
    cmd_host.exec_command(
        sudo=True, cmd=f"ceph mds fail {active_mds_rank(cmd_host)}", check_ec=False,
    )


def tc_07_mds_failover(ctx, tag):
    delay = int(ctx.config.get("mds_fail_delay_sec", 5))
    ctx.disrupt_since, _ = get_node_time(ctx.active)
    Thread(target=_mds_fail_later, args=(ctx.cmd, delay), daemon=True).start()
    gctx = GraceCtx(
        clients=ctx.clients, active=ctx.active, peers=ctx.peers, server=ctx.server,
        nfs_name=ctx.nfs_name, export=ctx.exports[0]["export"],
        mount=ctx.mounts[0], nfs_port=ctx.nfs_port,
    )
    gctx.holds = ctx.holds
    rc = enter_grace(gctx, target_node=ctx.server)[0]
    deadline = time.time() + RECOVERY_TIMEOUT
    while time.time() < deadline:
        out, _ = ctx.cmd.exec_command(sudo=True, cmd="ceph fs status cephfs", check_ec=False)
        if "degraded" not in (out or "").lower() and rc == 0:
            return 0
        time.sleep(10)
    if rc and not any(d.get("status_desc") == "running" for d in orch_nfs_daemons(ctx.cmd, ctx.nfs_name)):
        return 1
    return 0


def _reboot_mount_server(ctx, tag):
    ctx.disrupt_since, _ = get_node_time(ctx.active)
    log.info("[%s] reboot mount server %s", tag, ctx.server.hostname)
    return 0 if reboot_node(ctx.server) else 1


def tc_09_reboot_peers(ctx, tag):
    ctx.disrupt_since, _ = get_node_time(ctx.active)
    for node in ctx.peers:
        if not reboot_node(node):
            return 1
    return 0


WORKFLOWS = {
    "TC-01": ("Primary daemon rm + respawn", tc_01_daemon_rm_primary),
    "TC-02": ("Primary daemon restart", tc_02_daemon_restart_primary),
    "TC-03": ("Primary daemon redeploy", tc_03_daemon_redeploy_primary),
    "TC-04": ("Peer daemon rm", tc_04_daemon_rm_peers),
    "TC-05": ("Peer daemon restart", tc_05_daemon_restart_peers),
    "TC-06": ("Peer daemon redeploy", tc_06_daemon_redeploy_peers),
    "TC-07": ("MDS failover + grace", tc_07_mds_failover),
    "TC-08": ("Reboot mount server", _reboot_mount_server),
    "TC-09": ("Reboot peer nfs nodes", tc_09_reboot_peers),
    "TC-10": ("Reboot mount server (4-host pool)", _reboot_mount_server),
}


def _run_one_tc(ctx, tc_id, tc10_pool, coredump_since):
    desc, fn = WORKFLOWS.get(tc_id, (None, None))
    if not fn:
        return "failed"
    announce(f"Integration [{tc_id}] — {desc}")
    if tc_id == "TC-10":
        if len(ctx.all_nfs_nodes) < tc10_pool:
            log.info("[%s] skipped (need %s NFS nodes for 4-host pool)", tc_id, tc10_pool)
            return "skipped"
        if not _prepare_tc10_placement(ctx):
            return "failed"
    try:
        pre_workflow(ctx, tc_id)
        mid_rc = fn(ctx, tc_id)
        if mid_rc is None:
            return "skipped"
        if mid_rc or post_workflow(ctx, tc_id):
            return "failed"
        if check_coredumps(ctx.pool_nodes, coredump_since, tc_id):
            return "failed"
        return "passed"
    except Exception as exc:
        log.error("[%s] FAILED: %s", tc_id, exc)
        return "failed"


def run(ceph_cluster, **kw):
    config = kw.get("config") or {}
    selected = config.get("workflows") or list(WORKFLOWS)
    nfs_nodes = resolve_nfs_nodes(ceph_cluster)
    clients = ceph_cluster.get_nodes("client")
    installer = ceph_cluster.get_nodes("installer")[0]
    nfs_count = int(config.get("nfs_count", DEFAULT_NFS_COUNT))
    tc10_pool = nfs_count + TC10_POOL_EXTRA
    min_nfs = tc10_pool if "TC-10" in selected else nfs_count

    results = {}
    ctx = None
    try:
        if len(nfs_nodes) < min_nfs or len(clients) < INTEG_CLIENT_COUNT:
            log.error("Need >=%s NFS nodes and >=%s clients", min_nfs, INTEG_CLIENT_COUNT)
            results["setup"] = "failed"
        else:
            announce("Deploy shared TSM integration cluster")
            ctx = deploy_shared_cluster(
                ceph_cluster, installer, clients[:INTEG_CLIENT_COUNT], nfs_nodes, config,
            )
            if ctx is None:
                results["deploy"] = "failed"
            else:
                _, coredump_since = get_node_time(ctx.pool_nodes)
                try:
                    announce("Start suite holds (3 exports)")
                    setup_suite_holds(ctx)
                except Exception as exc:
                    log.error("Suite hold setup failed: %s", exc)
                    results["holds"] = "failed"
                else:
                    for tc_id in selected:
                        results[tc_id] = _run_one_tc(ctx, tc_id, tc10_pool, coredump_since)
    finally:
        if ctx:
            _teardown_integ(ctx=ctx)

    return log_workflow_summary(results, title=SUMMARY_TITLE, name_width=SUMMARY_WIDTH)
