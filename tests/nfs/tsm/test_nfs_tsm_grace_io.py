"""NFS TSM grace-period IO workflows.

Dict-driven suite for grace scenarios (OPEN / LOCK / DELEG × clients).
Add new TCs to WORKFLOWS; each entry points at a handler that receives a
shared GraceCtx after one TSM deploy + mount.

TC-TSM-G-O01: Client A write-open hold → peer open sync → restart into grace
→ reclaim via held FD → peer open still present.
"""

import json
import time

from tests.nfs.lib.common_lib import get_nfs_container_id, get_node_time, scrape_nfs_logs
from tests.nfs.lib.tsm.helpers import (
    POLL_INTERVAL,
    POLL_TIMEOUT,
    announce,
    check_coredumps,
    fmt_tsm,
    kill_holds as _kill_holds,
    log_workflow_summary,
    mount_clients as _mount_clients,
    peer_summary as _peer_summary,
    start_bg as _bg,
    wait_peer_counts,
)
from tests.nfs.tsm.test_nfs_tsm_basic import deploy_step, safe_cleanup
from utility.log import Log

log = Log(__name__)

GRACE_IN_RE = r"NFS Server Now IN GRACE"
GRACE_OUT_RE = r"NFS Server Now NOT IN GRACE"

TSM_PORT = 36369
GRACE_TIMEOUT = 120
CONTAINER_TIMEOUT = 120


# ---------------------------------------------------------------------------
# Shared context for all grace TCs (filled once in run())
# ---------------------------------------------------------------------------
class GraceCtx:
    """Cluster handles shared by every WORKFLOWS handler."""

    def __init__(
        self,
        clients,
        active,
        peers,
        server,
        nfs_name,
        export,
        mount,
        nfs_port,
    ):
        self.clients = clients
        self.active = active
        self.peers = peers
        self.server = server
        self.nfs_name = nfs_name
        self.export = export
        self.mount = mount
        self.nfs_port = nfs_port
        self.holds = []  # list of (client, pid) started by handlers

    @property
    def client_a(self):
        return self.clients[0]

    @property
    def client_b(self):
        return self.clients[1] if len(self.clients) > 1 else None

    @property
    def client_c(self):
        return self.clients[2] if len(self.clients) > 2 else None


# ---------------------------------------------------------------------------
# Peer TSM record helpers (shared via lib/tsm/helpers.py)
# ---------------------------------------------------------------------------
def _wait_counts(peers, nfs_name, since, expect_open, expect_lock, label):
    """Poll peer summaries until open/lock match expected values."""
    return (
        0
        if wait_peer_counts(
            peers, nfs_name, since, expect_open, expect_lock, label
        )
        is not None
        else 1
    )


def _wait_open_at_least(peers, nfs_name, since, min_open, label):
    """Poll until peer open count is >= min_open."""
    deadline = time.time() + POLL_TIMEOUT
    last = None
    while time.time() < deadline:
        last = _peer_summary(peers, nfs_name, since=since)
        if last.get("seen") and last["open"] >= min_open:
            log.info("[%s] peer open=%s (>= %s)", label, last["open"], min_open)
            return 0, last
        time.sleep(POLL_INTERVAL)
    log.error(
        "[%s] peer open timeout: want >= %s last=%s", label, min_open, last
    )
    return 1, last


# ---------------------------------------------------------------------------
# Hold / kill helpers
# ---------------------------------------------------------------------------
def _pid_alive(client, pid):
    out, _ = client.exec_command(
        sudo=True, cmd=f"kill -0 {pid} 2>/dev/null && echo alive", check_ec=False
    )
    return "alive" in (out or "")


# ---------------------------------------------------------------------------
# Grace / daemon restart helpers
# ---------------------------------------------------------------------------
def _nfs_daemon_on_host(client, nfs_name, hostname):
    out, _ = client.exec_command(
        sudo=True,
        cmd=f"ceph orch ps --service_name nfs.{nfs_name} --format json",
    )
    daemons = json.loads(out or "[]")
    return next((d for d in daemons if d.get("hostname") == hostname), None)


def _restart_nfs_daemon(client, nfs_name, hostname):
    daemon = _nfs_daemon_on_host(client, nfs_name, hostname)
    if not daemon or not daemon.get("daemon_name"):
        log.error("No nfs.%s daemon on %s", nfs_name, hostname)
        return False
    name = daemon["daemon_name"]
    log.info("Restarting daemon %s on %s", name, hostname)
    client.exec_command(sudo=True, cmd=f"ceph orch daemon restart {name} --force")
    return True


def _wait_new_container(node, nfs_name, old_cid, timeout=CONTAINER_TIMEOUT):
    for _ in range(max(1, timeout // 2)):
        cid = get_nfs_container_id(node, nfs_name=nfs_name)
        if cid and cid != old_cid:
            log.info("New NFS container on %s: %s (was %s)", node.hostname, cid, old_cid)
            return cid
        time.sleep(2)
    log.error("Timed out waiting for new container on %s", node.hostname)
    return None


def _wait_log_pattern(nodes, nfs_name, pattern, since, label, timeout=GRACE_TIMEOUT):
    """Wait until scrape_nfs_logs finds pattern on any node."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        hits = scrape_nfs_logs(nodes, pattern, nfs_name=nfs_name, since=since)
        if hits and any(hits.get(n.hostname) for n in nodes):
            log.info("[%s] matched %r", label, pattern)
            return 0
        time.sleep(POLL_INTERVAL)
    log.error("[%s] timed out waiting for %r", label, pattern)
    return 1


def enter_grace(ctx, target_node=None):
    """Restart NFS on target (default: mount server); wait IN GRACE.

    Returns (0, grace_since) on success, (1, None) on failure.
    Updates ctx.active peers' containers after restart.
    """
    node = target_node or ctx.server
    client = ctx.client_a
    old_cid = get_nfs_container_id(node, nfs_name=ctx.nfs_name)
    grace_since, _ = get_node_time([node])

    if not _restart_nfs_daemon(client, ctx.nfs_name, node.hostname):
        return 1, None

    if old_cid:
        if not _wait_new_container(node, ctx.nfs_name, old_cid):
            return 1, None

    # Prefer the restarted node for grace marker; also check all actives
    watch = [node] + [n for n in ctx.active if n.hostname != node.hostname]
    if _wait_log_pattern(
        watch, ctx.nfs_name, GRACE_IN_RE, grace_since, "enter_grace"
    ):
        return 1, None
    return 0, grace_since


# ---------------------------------------------------------------------------
# TC handlers — add new scenarios here and register in WORKFLOWS
# ---------------------------------------------------------------------------
def tc_tsm_g_o01(ctx):
    """TC-TSM-G-O01: Grace reclaim write-open (1 client)."""
    tag = "TC-TSM-G-O01"
    client = ctx.client_a
    path = f"{ctx.mount}/tsm_grace_o01.txt"
    hold_cmd = (
        f"bash -c 'exec 3>{path}; echo held >&3; sync; sleep infinity'"
    )

    baseline_since, _ = get_node_time(ctx.peers)
    baseline = _peer_summary(ctx.peers, ctx.nfs_name, since=baseline_since)
    base_open = baseline["open"] if baseline.get("seen") else 0
    log.info("[%s] baseline open=%s", tag, base_open)

    hold_since, _ = get_node_time(ctx.peers)
    announce(
        "Do open + hold [%s]" % tag,
        fmt_tsm(base_open + 1, baseline.get("lock", 0) if baseline.get("seen") else 0),
    )
    pid = _bg(client, hold_cmd)
    if not pid:
        return 1
    ctx.holds.append((client, pid))

    if _wait_counts(
        ctx.peers,
        ctx.nfs_name,
        hold_since,
        base_open + 1,
        baseline.get("lock", 0) if baseline.get("seen") else 0,
        f"{tag}:while-held",
    ):
        # Fall back: open at least baseline+1 (lock may be noisy)
        rc, snap = _wait_open_at_least(
            ctx.peers, ctx.nfs_name, hold_since, base_open + 1, f"{tag}:open-at-least"
        )
        if rc:
            return 1

    # Restart mount server into grace while FD remains open
    if enter_grace(ctx, target_node=ctx.server)[0]:
        return 1

    # Reclaim: hold process still alive; write through held FD; read file back
    if not _pid_alive(client, pid):
        log.error("[%s] hold pid %s died during grace/restart", tag, pid)
        return 1

    # Write through the still-held FD (NFS reclaim path), then read file
    client.exec_command(
        sudo=True,
        cmd=f"bash -c 'echo reclaimed > /proc/{pid}/fd/3'",
        check_ec=False,
    )
    cat, _ = client.exec_command(sudo=True, cmd=f"cat {path}", check_ec=False)
    text = (cat or "").strip()
    log.info("[%s] file content after reclaim write: %r", tag, text)
    if "held" not in text and "reclaimed" not in text:
        log.error("[%s] reclaim IO failed; file empty/missing", tag)
        return 1

    # Peer open should still reflect A's open after recovery
    post_since, _ = get_node_time(ctx.peers)
    rc, snap = _wait_open_at_least(
        ctx.peers, ctx.nfs_name, post_since, 1, f"{tag}:post-reclaim-open"
    )
    if rc:
        # Peers may need a moment after grace; one more poll without since floor
        rc, snap = _wait_open_at_least(
            ctx.peers, ctx.nfs_name, None, 1, f"{tag}:post-reclaim-open-any"
        )
        if rc:
            return 1

    log.info("[%s] PASSED (peer open=%s)", tag, snap.get("open") if snap else "?")
    return 0


# ---------------------------------------------------------------------------
# Registry — subsequent TCs: add handler + WORKFLOWS entry only
# ---------------------------------------------------------------------------
WORKFLOWS = {
    "TC-TSM-G-O01": {
        "desc": "Grace reclaim write-open (1 client)",
        "min_clients": 1,
        "run": tc_tsm_g_o01,
    },
    # Future examples (uncomment / add handlers when automating):
    # "TC-TSM-G-O04": {
    #     "desc": "Non-conflict write-open other file during grace (2 clients)",
    #     "min_clients": 2,
    #     "run": tc_tsm_g_o04,
    # },
    # "TC-TSM-G-L01": {
    #     "desc": "Grace reclaim exclusive lock (1 client)",
    #     "min_clients": 1,
    #     "run": tc_tsm_g_l01,
    # },
}


def run(ceph_cluster, **kw):
    """Deploy TSM once, run all registered grace WORKFLOWS, then cleanup."""
    config = kw.get("config") or {}
    selected = config.get("workflows")  # optional list of TC ids
    nfs_version = str(config.get("nfs_version", "4.2"))

    nfs_nodes = sorted(ceph_cluster.get_nodes("nfs"), key=lambda n: n.hostname)
    clients = ceph_cluster.get_nodes("client")
    installer = ceph_cluster.get_nodes("installer")[0]
    if len(nfs_nodes) < 2 or not clients:
        log.error("Need ≥2 NFS nodes and ≥1 client")
        return 1

    need_clients = max(spec.get("min_clients", 1) for spec in WORKFLOWS.values())
    if selected:
        need_clients = max(
            WORKFLOWS[n].get("min_clients", 1)
            for n in selected
            if n in WORKFLOWS
        )
    if len(clients) < need_clients:
        log.error("Need ≥%s clients for selected grace workflows", need_clients)
        return 1

    nodes = nfs_nodes[:2]
    use_clients = clients[: max(need_clients, 1)]
    name = "tsmg-grace"
    nfs_name = f"cephfs-nfs-{name}"
    export = f"/export_{name}"
    mount = f"/mnt/nfs_{name}"
    results = {}

    ctx = None
    try:
        result = deploy_step(
            ceph_cluster,
            installer,
            use_clients[0],
            nodes,
            {"nfs_count": 2, "tsm_port": TSM_PORT},
            nfs_name,
            name,
        )
        if result is None:
            return 1
        _, active, nfs_port, _ = result
        server, peers = active[0], active[1:]

        if _mount_clients(
            use_clients,
            nfs_name,
            export,
            mount,
            nfs_port,
            server.hostname,
            nfs_version=nfs_version,
        ):
            return 1

        ctx = GraceCtx(
            clients=use_clients,
            active=active,
            peers=peers,
            server=server,
            nfs_name=nfs_name,
            export=export,
            mount=mount,
            nfs_port=nfs_port,
        )

        cases = selected or list(WORKFLOWS.keys())
        _, coredump_since = get_node_time(nodes)
        for i, tc_id in enumerate(cases, 1):
            spec = WORKFLOWS.get(tc_id)
            if not spec:
                log.error("Unknown workflow %s", tc_id)
                results[tc_id] = "failed"
                continue
            if len(use_clients) < spec.get("min_clients", 1):
                log.warning("[%s] skip (need %s clients)", tc_id, spec["min_clients"])
                results[tc_id] = "skipped"
                continue

            log.info(
                "\n==============================\n"
                "Test %s: %s: %s\n"
                "==============================",
                i,
                tc_id,
                spec.get("desc", ""),
            )
            announce("Do workflow [%s] — %s" % (tc_id, spec.get("desc", "")))
            # Drop holds from previous TC before next
            if ctx.holds:
                _kill_holds(ctx.holds)
                ctx.holds = []
                time.sleep(2)

            try:
                rc = spec["run"](ctx)
                results[tc_id] = "passed" if rc == 0 else "failed"
            except Exception as exc:
                log.error("[%s] FAILED: %s", tc_id, exc)
                results[tc_id] = "failed"
            if results[tc_id] == "passed" and check_coredumps(
                nodes, coredump_since, tc_id
            ):
                results[tc_id] = "failed"
            _, coredump_since = get_node_time(nodes)
    except Exception as exc:
        log.error("Grace IO suite FAILED: %s", exc)
        return 1
    finally:
        if ctx and ctx.holds:
            _kill_holds(ctx.holds)
        safe_cleanup(use_clients[0], mount, nfs_name, export, nodes)
        for client in use_clients[1:]:
            client.exec_command(
                sudo=True,
                cmd=f"umount -l {mount} 2>/dev/null",
                check_ec=False,
            )

    return log_workflow_summary(results, title="TSM GRACE IO SUMMARY")
