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
    collect_tsm_node_ids,
    get_host_tsm_node_id,
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
from tests.nfs.lib.tsm.grace_hold import GraceCtx, enter_grace
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
        # Clients mount this host; never reassign from "first active" after reboot/rm.
        self.mount_hostname = active[0].hostname
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
        # TC-04/05/06/09: post checks peer Node-ids == 0 and mount server retains baseline.
        self.peer_disrupt_post = False
        # hostname → TSM Node-id, captured once after deploy (stable across disrupt).
        self.tsm_node_ids = {}
        # Mount-server TSM Node-id (baseline open/lock/deleg live here, not on peer ids).
        self.server_nid = None
        self.all_nfs_nodes = []
        self.validator = NfsTsmValidation(ceph_cluster, clients[0], "enable_TSM", "Tsm_Port", TSM_PORT)


def _refresh_active(ctx):
    """Refresh running NFS nodes; keep mount server identity pinned."""
    active = nodes_running_nfs(ctx.pool_nodes, ctx.nfs_name)
    if not active:
        return active
    ctx.active = active
    mount_hn = ctx.mount_hostname or (ctx.server.hostname if ctx.server else None)
    if mount_hn:
        # Prefer the pinned mount host even if its container is briefly down.
        server = next((n for n in ctx.pool_nodes if n.hostname == mount_hn), None)
        if server is None:
            server = next((n for n in active if n.hostname == mount_hn), None)
        if server is not None:
            ctx.server = server
        ctx.peers = [n for n in active if n.hostname != mount_hn]
    else:
        ctx.server = active[0]
        ctx.peers = active[1:]
        ctx.mount_hostname = ctx.server.hostname
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
    announce("Collect TSM Node-ids from podman logs (Ganesha ID)")
    ctx.tsm_node_ids = collect_tsm_node_ids(ctx.active, NFS_NAME)
    if len(ctx.tsm_node_ids) < len(ctx.active):
        missing = [n.hostname for n in ctx.active if n.hostname not in ctx.tsm_node_ids]
        return _deploy_fail(f"Missing TSM Node-id for: {missing}", clients, pool, ctx)
    ctx.server_nid = ctx.tsm_node_ids.get(ctx.server.hostname)
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
    # Placement may move daemons; refresh Node-id map for current active set.
    ctx.tsm_node_ids.update(collect_tsm_node_ids(ctx.active, ctx.nfs_name))
    ctx.server_nid = ctx.tsm_node_ids.get(ctx.server.hostname, ctx.server_nid)
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


def _nid_for(ctx, node, label):
    """Return stable TSM Node-id for node from post-deploy map (grace-io style)."""
    nid = ctx.tsm_node_ids.get(node.hostname)
    if nid is not None:
        return nid
    # Fallback live scrape only if map missed this host (e.g. TC-10 new placement).
    nid = get_host_tsm_node_id(node, ctx.nfs_name)
    if nid is not None:
        ctx.tsm_node_ids[node.hostname] = nid
        log.info("[%s] cached TSM Node-id %s=%s from live lookup", label, node.hostname, nid)
        return nid
    log.error("[%s] no TSM Node-id for %s (not in deploy map)", label, node.hostname)
    return None


def _resolve_server_nid(ctx, label):
    """Return pinned mount-server TSM Node-id (deploy map); never follow active[0]."""
    if ctx.server_nid is not None:
        return ctx.server_nid
    # Resolve via pinned mount hostname, not whatever _refresh_active last saw.
    mount_hn = ctx.mount_hostname or (ctx.server.hostname if ctx.server else None)
    if mount_hn and mount_hn in ctx.tsm_node_ids:
        ctx.server_nid = ctx.tsm_node_ids[mount_hn]
        return ctx.server_nid
    if ctx.server is not None:
        nid = _nid_for(ctx, ctx.server, label)
        if nid is not None:
            ctx.server_nid = nid
            return nid
    log.error(
        "[%s] no TSM Node-id for mount server %s",
        label, mount_hn or "<unknown>",
    )
    return None


def _wait_server_nid_counts(
    ctx,
    hosts,
    since,
    label,
    expect_open=None,
    expect_lock=None,
    expect_deleg=None,
    timeout=RECOVERY_TIMEOUT,
):
    """Wait for counts on mount-server Node-id in ``hosts`` TSM summaries.

    Defaults to ``ctx.want_tsm`` when expect_* are omitted.
    """
    w = ctx.want_tsm or {}
    open_c = w["open"] if expect_open is None else expect_open
    lock_c = w["lock"] if expect_lock is None else expect_lock
    deleg_c = w.get("deleg", 0) if expect_deleg is None else expect_deleg
    nid = _resolve_server_nid(ctx, label)
    if nid is None:
        return None
    return wait_peer_counts(
        hosts,
        ctx.nfs_name,
        since,
        open_c,
        lock_c,
        label,
        expect_deleg=deleg_c,
        timeout=timeout,
        node_id=nid,
    )


def setup_suite_holds(ctx):
    """Start all holds once after deploy."""
    _refresh_active(ctx)
    ctx.hold_since, _ = get_node_time(ctx.peers)
    if _resolve_server_nid(ctx, "setup") is None:
        raise RuntimeError("setup: no TSM Node-id on mount server")
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
        # Peers print mount-server Node-id as holds sync — not the peer's own id.
        if _wait_server_nid_counts(
            ctx,
            ctx.peers,
            ctx.hold_since,
            f"setup:hold{i}",
            expect_open=cur_o,
            expect_lock=cur_l,
            expect_deleg=cur_d,
        ) is None:
            raise RuntimeError(f"setup hold {i} peer TSM timeout")
    ctx.want_tsm = {"open": cur_o, "lock": cur_l, "deleg": cur_d}


def pre_workflow(ctx, tag):
    _refresh_active(ctx)
    ctx.mds_pre = snapshot_mds_sessions(ctx.cmd, f"{tag}:pre")
    ctx.ganesha_id = record_ganesha_id(ctx.cmd, ctx.nfs_name)
    # Baseline open/lock/deleg is on mount-server Node-id. After peer disrupt,
    # peers only print their own Node-ids at 0 — do not use unfiltered peer last-line.
    if _wait_server_nid_counts(
        ctx, [ctx.server], ctx.hold_since, f"{tag}:pre",
    ) is None:
        raise RuntimeError(f"[{tag}] pre-workflow mount-server TSM not at baseline")


def _post_peer_disrupt(ctx, tag):
    """Peer-disrupt post: peer Node-ids empty after disrupt; mount server keeps baseline."""
    _refresh_active(ctx)

    for peer in ctx.peers:
        # Use deploy-time map — live Ganesha ID scrape often misses after peer restart/rm.
        nid = _nid_for(ctx, peer, tag)
        if nid is None:
            return 1
        if wait_peer_counts(
            [peer],
            ctx.nfs_name,
            ctx.disrupt_since,
            0,
            0,
            f"{tag}:peer-zero Node-id={nid}",
            expect_deleg=0,
            timeout=RECOVERY_TIMEOUT,
            node_id=nid,
        ) is None:
            return 1

    if _wait_server_nid_counts(
        ctx, [ctx.server], ctx.hold_since, f"{tag}:primary-retain",
    ) is None:
        return 1
    return 0


def post_workflow(ctx, tag):
    _refresh_active(ctx)
    log_since = ctx.disrupt_since or ctx.hold_since
    try:
        if ctx.peer_disrupt_post:
            if _post_peer_disrupt(ctx, tag):
                return 1
        else:
            # Prefer peers' view of mount-server Node-id (primary disrupt / reboot).
            # After peer-disrupt TCs peers stop publishing that Node-id — use server.
            nid = _resolve_server_nid(ctx, f"{tag}:post")
            if nid is None:
                return 1
            probe = peer_summary(
                ctx.peers, ctx.nfs_name, since=log_since, node_id=nid,
            )
            hosts = ctx.peers if probe.get("seen") else [ctx.server]
            if not probe.get("seen"):
                log.info(
                    "[%s] peers have no Node-id=%s summary; checking mount server",
                    tag, nid,
                )
            if _wait_server_nid_counts(
                ctx, hosts, log_since, f"{tag}:post",
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
    finally:
        ctx.peer_disrupt_post = False


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
    # Mid-rm: peers must still show mount-server Node-id baseline (not peer ids).
    if _wait_server_nid_counts(
        ctx, ctx.peers, ctx.disrupt_since, f"{tag}:mid-rm",
    ) is None:
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
    ctx.peer_disrupt_post = True
    peers = _peer_hosts(ctx)
    ctx.disrupt_since, _ = get_node_time(ctx.active)
    for host in peers:
        remove_nfs_daemon(ctx.cmd, ctx.nfs_name, host)
    return 0 if wait_orch_hosts(ctx.cmd, ctx.nfs_name, peers) else 1


def tc_05_daemon_restart_peers(ctx, tag):
    ctx.peer_disrupt_post = True
    ctx.disrupt_since, _ = get_node_time(ctx.active)
    return _for_hosts(ctx, _peer_hosts(ctx), restart_nfs_daemon)


def tc_06_daemon_redeploy_peers(ctx, tag):
    ctx.peer_disrupt_post = True
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
    host = ctx.mount_hostname or ctx.server.hostname
    ctx.disrupt_since, _ = get_node_time(ctx.active)
    log.info("[%s] reboot mount server %s (Node-id=%s)", tag, host, ctx.server_nid)
    if not reboot_node(ctx.server):
        return 1
    # Wait for NFS to return on the pinned mount host before post checks.
    if not wait_daemon_running(ctx.cmd, ctx.nfs_name, host):
        log.error("[%s] NFS daemon not running on mount server %s after reboot", tag, host)
        return 1
    _refresh_active(ctx)
    return 0


def tc_09_reboot_peers(ctx, tag):
    ctx.peer_disrupt_post = True
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
    finally:
        ctx.peer_disrupt_post = False


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
