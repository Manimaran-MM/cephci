"""Shared TSM test helpers used by basic/record/grace/delegation workflows."""

import re
import shlex
import time

from cli.ceph.ceph import Ceph
from cli.exceptions import OperationFailedError
from cli.utilities.filesys import Mount
from cli.utilities.utils import check_coredump_generated
from tests.nfs.lib.common_lib import get_nfs_container_id
from tests.nfs.lib.multi_active.config import NfsMultiActiveConfig
from tests.nfs.lib.tsm.constants import NfsFcntlLock
from utility.log import Log

log = Log(__name__)

SUMMARY_RE = re.compile(
    r"Tsm record summary total=(\d+) open=(\d+) lock=(\d+) deleg=(\d+)", re.I
)
# "Node id: N" / "Nodeid: N" both appear in tsm_print_node_state.
NODE_SUMMARY_RE = re.compile(
    r"Node\s*id:\s*(-?\d+)\s+Tsm record summary "
    r"total=(\d+) open=(\d+) lock=(\d+) deleg=(\d+)",
    re.I,
)
GANESHA_ID_RE = re.compile(r"Ganesha ID:\s*(\d+)", re.I)
POLL_TIMEOUT = 90
POLL_INTERVAL = 3
COREDUMP_PATH = "/var/lib/systemd/coredump"


def _podman_logs(node, nfs_name, since=None):
    """Return (cid, log_text). cid is None if the NFS container is missing."""
    cid = get_nfs_container_id(node, nfs_name=nfs_name)
    if not cid:
        return None, ""
    node_since = since.get(node.hostname) if isinstance(since, dict) else since
    since_arg = f' --since "{node_since}"' if node_since else ""
    out, _ = node.exec_command(
        sudo=True, cmd=f"podman logs{since_arg} {cid} 2>&1", check_ec=False
    )
    return cid, out or ""


def _bump_counts(counts, total, open_c, lock_c, deleg_c):
    counts["seen"] = True
    counts["total"] = max(counts["total"], int(total))
    counts["open"] = max(counts["open"], int(open_c))
    counts["lock"] = max(counts["lock"], int(lock_c))
    counts["deleg"] = max(counts["deleg"], int(deleg_c))


def get_host_tsm_node_id(node, nfs_name):
    """Return NFS host's TSM id from ``Ganesha ID: N`` in podman logs."""
    _, out = _podman_logs(node, nfs_name)
    node_id = None
    for ln in out.splitlines():
        m = GANESHA_ID_RE.search(ln)
        if m:
            node_id = int(m.group(1))
    if node_id is not None:
        log.info("TSM Node-id on %s = %s (from Ganesha ID)", node.hostname, node_id)
    else:
        log.warning(
            "TSM Node-id not found on %s (no 'Ganesha ID: N' in podman logs)",
            node.hostname,
        )
    return node_id


def collect_tsm_node_ids(nodes, nfs_name):
    """Map hostname → TSM Node-id for each NFS host (stable after deploy)."""
    mapping = {}
    for node in nodes:
        nid = get_host_tsm_node_id(node, nfs_name)
        if nid is not None:
            mapping[node.hostname] = nid
    log.info("TSM Node-id map (post-deploy): %s", mapping)
    return mapping


def peer_summary(peers, nfs_name, since=None, node_id=None):
    """Last peer TSM summary from ``podman logs``.

    If ``node_id`` is set, only match that Node-id record.
    """
    counts = {"total": 0, "open": 0, "lock": 0, "deleg": 0, "seen": False}
    for node in peers:
        _, out = _podman_logs(node, nfs_name, since=since)
        lines = [ln for ln in out.splitlines() if SUMMARY_RE.search(ln)]

        if node_id is not None:
            matched, last_m = [], None
            for ln in lines:
                nm = NODE_SUMMARY_RE.search(ln)
                if nm and int(nm.group(1)) == int(node_id):
                    matched.append(ln)
                    last_m = nm
            log.info(
                "TSM record summary on %s (Node-id %s):\n%s",
                node.hostname,
                node_id,
                "\n".join(matched[-3:]) if matched else "<none>",
            )
            if last_m:
                _bump_counts(counts, *last_m.group(2, 3, 4, 5))
            continue

        log.info(
            "TSM record summary on %s:\n%s",
            node.hostname,
            "\n".join(lines[-3:]) if lines else "<none>",
        )
        if not lines:
            continue
        m = SUMMARY_RE.search(lines[-1])
        if m:
            _bump_counts(counts, *m.group(1, 2, 3, 4))
    return counts


def wait_peer_counts(
    peers,
    nfs_name,
    since,
    expect_open,
    expect_lock,
    label,
    expect_deleg=None,
    timeout=POLL_TIMEOUT,
    interval=POLL_INTERVAL,
    raise_on_timeout=False,
    node_id=None,
):
    """Poll until peer open/lock/(optional deleg) match.

    Return counts on success. On timeout: raise if ``raise_on_timeout``, else None.
    """
    deadline = time.time() + timeout
    last = None
    want = fmt_tsm(expect_open, expect_lock, expect_deleg)
    nid_s = f" Node-id={node_id}" if node_id is not None else ""

    while time.time() < deadline:
        last = peer_summary(peers, nfs_name, since=since, node_id=node_id)
        if (
            last.get("seen")
            and last["open"] == expect_open
            and last["lock"] == expect_lock
            and (expect_deleg is None or last["deleg"] == expect_deleg)
        ):
            log.info("[%s] peer summary ok (%s)%s", label, want, nid_s)
            return last
        time.sleep(interval)

    log.error(
        "[%s] peer summary timeout: want %s node_id=%s last=%s",
        label,
        want,
        node_id,
        last,
    )
    if raise_on_timeout:
        raise OperationFailedError("[%s] TSM timeout want %s" % (label, want))
    return None


def start_bg(client, cmd):
    """Start cmd in background; return pid string or None."""
    out, _ = client.exec_command(
        sudo=True,
        cmd=f"nohup bash -c {shlex.quote(cmd)} >/dev/null 2>&1 & echo $!",
        check_ec=False,
    )
    pid = (out or "").strip().splitlines()[-1] if out else ""
    if not pid.isdigit():
        log.error("Failed to start bg on %s: %r cmd=%r", client.hostname, out, cmd)
        return None
    log.info("Started pid=%s on %s: %s", pid, client.hostname, cmd)
    return pid


def kill_holds(holds):
    """Best-effort kill of (client, pid) holds. Safe if holds is empty/None."""
    for client, pid in holds or []:
        NfsFcntlLock.kill_pid(client, pid)


def check_coredumps(nodes, since, tag):
    """Return 0 if ok, 1 if a new coredump appeared since ``since``.

    ``since``: {hostname: datetime} from ``get_node_time`` (coredump_since).
    """
    if not isinstance(nodes, (list, tuple)):
        nodes = [nodes]
    since = since or {}
    for node in nodes:
        ts = since.get(node.hostname)
        if ts and check_coredump_generated(node, COREDUMP_PATH, ts):
            log.error("[%s] coredump on %s", tag, node.hostname)
            return 1
    log.info("[%s] no coredumps", tag)
    return 0


def mount_clients(clients, nfs_name, export, mount, nfs_port, server, nfs_version="4.2"):
    """Create export and mount on each client. Return 0 ok, 1 on mount failure."""
    Ceph(clients[0]).nfs.export.create(
        fs_name="cephfs", nfs_name=nfs_name, nfs_export=export, fs="cephfs"
    )
    NfsMultiActiveConfig.wait_until_export_visible(clients[0], nfs_name, export)
    for client in clients:
        client.create_dirs(dir_path=mount, sudo=True)
        if Mount(client).nfs(
            mount=mount,
            version=str(nfs_version),
            port=str(nfs_port),
            server=server,
            export=export,
        ):
            log.error("Mount failed on %s", client.hostname)
            return 1
    return 0


def ensure_deleg_export(ctx, nfs_version="4.2"):
    """Create/mount ``ctx.deleg_export`` with ``delegations=rw`` once.

    Requires ``ctx.deleg_export``, ``ctx.deleg_mount``, ``ctx.clients``,
    ``ctx.nfs_name``, ``ctx.nfs_port``, ``ctx.server``. Return 0 ok, 1 fail.
    """
    if getattr(ctx, "_deleg_ready", False):
        return 0
    if not getattr(ctx, "deleg_export", None) or not getattr(ctx, "deleg_mount", None):
        log.error("ctx.deleg_export / ctx.deleg_mount not set")
        return 1

    client = ctx.client_a
    announce(f"Create/mount deleg export {ctx.deleg_export} (delegations=rw)")
    try:
        Ceph(client).nfs.export.create(
            fs_name="cephfs",
            nfs_name=ctx.nfs_name,
            nfs_export=ctx.deleg_export,
            fs="cephfs",
        )
    except Exception as exc:
        log.warning("deleg export create: %s (may already exist)", exc)
    try:
        client.exec_command(
            sudo=True,
            cmd=f"ceph nfs export update {ctx.nfs_name} {ctx.deleg_export} rw",
        )
    except Exception as exc:
        log.error("set delegations=rw on %s failed: %s", ctx.deleg_export, exc)
        return 1
    out, _ = client.exec_command(
        sudo=True,
        cmd=f"ceph nfs export info {ctx.nfs_name} {ctx.deleg_export} -f json",
        check_ec=False,
    )
    if "rw" not in (out or "").lower():
        log.warning(
            "delegations=rw not confirmed in export info (got %r); continuing",
            (out or "")[:200],
        )
    NfsMultiActiveConfig.wait_until_export_visible(
        client, ctx.nfs_name, ctx.deleg_export
    )
    for c in ctx.clients:
        c.create_dirs(dir_path=ctx.deleg_mount, sudo=True)
        out, _ = c.exec_command(
            sudo=True,
            cmd=f"mountpoint -q {ctx.deleg_mount} && echo ok",
            check_ec=False,
        )
        if "ok" in (out or ""):
            continue
        if Mount(c).nfs(
            mount=ctx.deleg_mount,
            version=str(nfs_version),
            port=str(ctx.nfs_port),
            server=ctx.server.hostname,
            export=ctx.deleg_export,
        ):
            log.error("Deleg mount failed on %s", c.hostname)
            return 1
    ctx._deleg_ready = True
    log.info("Deleg export ready: %s -> %s", ctx.deleg_export, ctx.deleg_mount)
    return 0


def file_base(mount, kind="wf"):
    """Path prefix for interactive/open_share files: ``{mount}/{kind}``."""
    return f"{mount.rstrip('/')}/{kind}"


def seed_wf_files(client, mount, indices, kind="wf"):
    """Create ``{kind}{i}.txt`` for each index (seed content, mode 666)."""
    for i in indices:
        path = f"{file_base(mount, kind)}{i}.txt"
        client.exec_command(
            sudo=True,
            cmd=f"bash -c 'echo seed > {path}; chmod 666 {path}'",
            check_ec=False,
        )


def workflow_peers(ctx):
    """Peers for TSM scrape (exclude spare while partitioned)."""
    peers = list(ctx.peers) if ctx.peers else list(ctx.active[1:])
    if not ctx.spare_node:
        return peers
    return [n for n in peers if n.hostname != ctx.spare_node.hostname]


def close_interactive(sess, indexes=None, unlock_indexes=None):
    """Unlock/close held indexes then stop InteractiveSession. No-op if None."""
    if not sess:
        return
    if indexes is None:
        indexes = []
    elif isinstance(indexes, int):
        indexes = [indexes]
    unlock_indexes = set(unlock_indexes or [])
    try:
        for idx in indexes:
            if idx in unlock_indexes:
                sess.send(f"unlock {idx}")
                time.sleep(1)
            sess.send(f"close {idx}")
            time.sleep(1)
        sess.stop()
    except Exception as exc:
        log.warning("interactive close/stop: %s", exc)


def mount_spare_export(ctx, nfs_version="4.2"):
    """Create/mount spare export once. Return 0 ok, 1 fail."""
    client = ctx.spare_client
    out, _ = client.exec_command(
        sudo=True,
        cmd=f"mountpoint -q {ctx.spare_mount} && echo ok",
        check_ec=False,
    )
    if "ok" in (out or ""):
        log.info("Spare already mounted at %s", ctx.spare_mount)
        return 0
    try:
        Ceph(client).nfs.export.create(
            fs_name="cephfs",
            nfs_name=ctx.nfs_name,
            nfs_export=ctx.spare_export,
            fs="cephfs",
        )
    except Exception as exc:
        log.warning("spare export create: %s (may already exist)", exc)
    NfsMultiActiveConfig.wait_until_export_visible(
        client, ctx.nfs_name, ctx.spare_export
    )
    client.create_dirs(dir_path=ctx.spare_mount, sudo=True)
    if Mount(client).nfs(
        mount=ctx.spare_mount,
        version=str(nfs_version),
        port=str(ctx.nfs_port),
        server=ctx.spare_node.hostname,
        export=ctx.spare_export,
    ):
        log.error("Spare mount failed on %s", client.hostname)
        return 1
    return 0


def start_spare_hold(ctx, file_idx=0):
    """Open-hold ``spare{file_idx}.txt`` via InteractiveSession. Return sess or None."""
    from tests.nfs.lib.tsm.interactive import (
        InteractiveSession,
        ensure_interactive_binary,
    )

    if ensure_interactive_binary(ctx.spare_client):
        return None
    base = file_base(ctx.spare_mount, "spare")
    sess = InteractiveSession(ctx.spare_client, base, tag="spare")
    if not sess.start():
        return None
    if sess.open_file(file_idx, "rwc", timeout=30) != "success":
        log.error("Spare open hold failed")
        sess.stop()
        return None
    log.info("Spare open hold active on %s", ctx.spare_client.hostname)
    return sess


def cleanup_grace_suite(ctx, clients, mount, nfs_name, export, nodes, safe_cleanup_fn):
    """Suite finally: release grace hold, umount spare/deleg/primary, delete cluster."""
    from tests.nfs.lib.tsm.grace_hold import release_cluster_grace

    if ctx:
        release_cluster_grace(ctx)
        if ctx.spare_client and ctx.spare_mount:
            ctx.spare_client.exec_command(
                sudo=True,
                cmd=f"umount -l {ctx.spare_mount} 2>/dev/null",
                check_ec=False,
            )
            try:
                Ceph(ctx.spare_client).nfs.export.delete(ctx.nfs_name, ctx.spare_export)
            except Exception as exc:
                log.warning("spare export delete: %s", exc)
        if getattr(ctx, "_deleg_ready", False) and ctx.deleg_mount:
            for c in ctx.clients:
                c.exec_command(
                    sudo=True,
                    cmd=f"umount -l {ctx.deleg_mount} 2>/dev/null",
                    check_ec=False,
                )
            try:
                Ceph(ctx.client_a).nfs.export.delete(ctx.nfs_name, ctx.deleg_export)
            except Exception as exc:
                log.warning("deleg export delete: %s", exc)
    for client in clients:
        client.exec_command(
            sudo=True, cmd=f"umount -l {mount} 2>/dev/null", check_ec=False
        )
    safe_cleanup_fn(clients[0], mount, nfs_name, export, nodes)


def fmt_tsm(open_c, lock_c, deleg_c=None):
    """Format open/lock/(optional deleg) for banners and errors."""
    if deleg_c is None:
        return "open=%s lock=%s" % (open_c, lock_c)
    return "open=%s lock=%s deleg=%s" % (open_c, lock_c, deleg_c)


def announce(action, expecting=None):
    """Banner for a workflow action (optionally with expected TSM counts)."""
    if expecting is None:
        log.info("\n******************** %s\n", action)
    else:
        log.info("\n******************** %s (Expecting: %s)\n", action, expecting)


def log_workflow_summary(results, title="TSM WORKFLOW SUMMARY", name_width=28):
    """Print pass/fail/skipped table. Return 1 if any failed, else 0."""
    passed = [n for n, s in results.items() if s == "passed"]
    failed = [n for n, s in results.items() if s == "failed"]
    skipped = [n for n, s in results.items() if s == "skipped"]
    rows = (
        "\n".join(f"  {n:<{name_width}} {s.upper()}" for n, s in results.items())
        if results
        else "  (no workflow tests recorded)"
    )
    log.info(
        "\n%s\n%s\n%s\n%s\n%s\n%s",
        "=" * 60,
        title,
        "=" * 60,
        rows,
        "-" * 60
        + f"\n  Total: {len(results)}  Passed: {len(passed)}  "
        f"Failed: {len(failed)}  Skipped: {len(skipped)}",
        "=" * 60,
    )
    return 1 if failed else 0


def run_step(
    results,
    test_num,
    name,
    fn,
    key=None,
    coredump_nodes=None,
    coredump_since=None,
):
    """Banner + run fn; record passed/failed in results. Return True on pass.

    Exceptions from ``fn`` are caught and recorded as failed (no re-raise).
    Optional coredump check after a successful ``fn``.
    """
    log.info(
        "\n==============================\n"
        "Test %s: %s\n"
        "==============================",
        test_num,
        name,
    )
    key = key if key is not None else "Test %s: %s" % (test_num, name)
    try:
        fn()
        if coredump_nodes is not None and check_coredumps(
            coredump_nodes, coredump_since, name
        ):
            results[key] = "failed"
            log.error("[Test %s] FAILED: coredump detected", test_num)
            return False
        results[key] = "passed"
        log.info("[Test %s] PASSED", test_num)
        return True
    except Exception as exc:
        log.error("[Test %s] FAILED: %s", test_num, exc)
        results[key] = "failed"
        return False
