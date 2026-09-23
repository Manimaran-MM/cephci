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
