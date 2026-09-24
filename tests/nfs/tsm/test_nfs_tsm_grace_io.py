"""NFS TSM grace-period IO conflict workflows.

Grace hold: spare open + iptables -I on spare client + spare NFS restart
→ ~90s cluster grace → C1/C2 conflict checks → unblock → after-grace TSM.

C01..C03: C1 WRITE_ONLY; C2 RO/WO/RW blocked then completes after grace.
C04..C06: C1 READ_ONLY; C2 RO succeeds during grace; C2 WO/RW blocked then
          completes after grace.
C07..C09: C1 READ_WRITE; C2 RO/WO/RW blocked then completes after grace.
C10: C1 WO+nwlock; C2 RW blocked at open → after grace open ok; nrlock+nwlock denied.
C11: C1 RO+nrlock; C2 RO+nrlock both succeed during grace (compatible).
C12: C1 RO+nrlock; C2 RW blocked → after grace open ok; nwlock denied then nrlock ok.
C13: deleg export type5; C1 WO+nwlock; C2 RW blocked → recall; nrlock+nwlock denied.
C14: deleg export type4; C1 RO+nrlock; C2 RW blocked → nwlock denied then nrlock ok.
C15: deleg export type4; C1 RO+nrlock; C2 RO+nrlock both succeed (deleg 1→2).
C16: pre-grace WO+nwlock on wf0; during grace C1 WO + C2 RO conflict on wf1; after open ok.
C17: pre-grace WO+nwlock on wf0; during grace C1 RO + C2 RO succeed on wf1 (compatible).
C18: pre-grace WO+nwlock on wf0; during grace C1 WO + C2 RW blocked on wf1;
     after open ok; nrlock+nwlock denied (pre-grace lock preserved).
C19: pre-grace RO+nrlock on wf0; during grace C1 WO + C2 RW blocked on wf1;
     after open ok; nwlock denied then nrlock success.
C20: pre-grace WO+nwlock on wf1; during grace C2 RO blocked on same file;
     after open ok; nrlock+nwlock denied (reclaim vs pre-grace open).
C21: deleg export; pre-grace WO+nwlock on wf0; during C1 WO+nwlock + C2 RW on wf1;
     after recall; nrlock+nwlock denied (sticky deleg preserved).
C22: pre-grace C1 WO+nwlock on wf0 + C2 RO+nrlock on wf2; during C1 WO + C2 RO
     blocked on wf1; after open ok (multi-client floor preserved).
"""

import re
import time

from cli.ceph.ceph import Ceph
from cli.utilities.filesys import Mount
from tests.nfs.lib.common_lib import get_nfs_container_id, get_node_time
from tests.nfs.lib.multi_active.config import NfsMultiActiveConfig
from tests.nfs.lib.tsm.grace_hold import (
    GraceCtx,
    enter_grace,
    hold_cluster_grace,
    release_cluster_grace,
    unblock_cluster_grace,
    wait_grace_exit,
)
from tests.nfs.lib.tsm.helpers import (
    announce,
    check_coredumps,
    collect_tsm_node_ids,
    fmt_tsm,
    log_workflow_summary,
    mount_clients as _mount_clients,
    peer_summary,
    wait_peer_counts,
)
from tests.nfs.lib.tsm.interactive import (
    InteractiveSession,
    ensure_interactive_binary,
)
from tests.nfs.tsm.test_nfs_tsm_basic import deploy_step, safe_cleanup
from utility.log import Log

# Re-export for integration (TC-07) and external importers.
__all__ = ["GraceCtx", "enter_grace", "run"]

log = Log(__name__)

TSM_PORT = 36369
DEFAULT_NFS_COUNT = 4
MIN_CLIENTS = 3  # C1 + C2 + spare hold client
SPARE_FILE_IDX = 0  # spare mount: spare0.txt
PRE_FILE_IDX = 0  # primary wf mount: wf0.txt (pre-grace sticky records)
WF_FILE_IDX = 1  # primary wf mount: wf1.txt (grace conflict)
PRE_C2_FILE_IDX = 2  # C22: C2 pre-grace sticky on wf2.txt

WO, RO, RW = "WRITE_ONLY", "READ_ONLY", "READ_WRITE"
SHARE_ACCESS = {RO: 1, WO: 2, RW: 3}

CONFLICT_SA_RE = re.compile(
    r"Open conflict existing_sa=(\d+) new_sa=(\d+)", re.I
)
CONFLICT_GRACE_RE = re.compile(
    r"Conflicting open\.\s*Return NFS4ERR_GRACE", re.I
)

# c2_expect: "blocked" → hang + after-grace complete; "success" → ok during grace.
WORKFLOWS = {
    "TC-TSM-G-C01": {
        "desc": "C1 WRITE_ONLY; C2 READ_ONLY blocked then completes after grace",
        "c1_mode": WO,
        "c2_mode": RO,
        "c2_expect": "blocked",
    },
    "TC-TSM-G-C02": {
        "desc": "C1 WRITE_ONLY; C2 WRITE_ONLY blocked then completes after grace",
        "c1_mode": WO,
        "c2_mode": WO,
        "c2_expect": "blocked",
    },
    "TC-TSM-G-C03": {
        "desc": "C1 WRITE_ONLY; C2 READ_WRITE blocked then completes after grace",
        "c1_mode": WO,
        "c2_mode": RW,
        "c2_expect": "blocked",
    },
    "TC-TSM-G-C04": {
        "desc": "C1 READ_ONLY; C2 READ_ONLY succeeds during grace (compatible)",
        "c1_mode": RO,
        "c2_mode": RO,
        "c2_expect": "success",
    },
    "TC-TSM-G-C05": {
        "desc": "C1 READ_ONLY; C2 WRITE_ONLY blocked then completes after grace",
        "c1_mode": RO,
        "c2_mode": WO,
        "c2_expect": "blocked",
    },
    "TC-TSM-G-C06": {
        "desc": "C1 READ_ONLY; C2 READ_WRITE blocked then completes after grace",
        "c1_mode": RO,
        "c2_mode": RW,
        "c2_expect": "blocked",
    },
    "TC-TSM-G-C07": {
        "desc": "C1 READ_WRITE; C2 READ_ONLY blocked then completes after grace",
        "c1_mode": RW,
        "c2_mode": RO,
        "c2_expect": "blocked",
    },
    "TC-TSM-G-C08": {
        "desc": "C1 READ_WRITE; C2 WRITE_ONLY blocked then completes after grace",
        "c1_mode": RW,
        "c2_mode": WO,
        "c2_expect": "blocked",
    },
    "TC-TSM-G-C09": {
        "desc": "C1 READ_WRITE; C2 READ_WRITE blocked then completes after grace",
        "c1_mode": RW,
        "c2_mode": RW,
        "c2_expect": "blocked",
    },
    # C1 WO + nwlock; C2 RW open blocked → after grace open ok; nrlock then nwlock denied
    "TC-TSM-G-C10": {
        "desc": (
            "C1 WO+nwlock; C2 RW blocked at open, after grace open ok; "
            "nrlock then nwlock denied"
        ),
        "c1_mode": WO,
        "c1_lock": "nwlock",
        "c2_mode": RW,
        "c2_expect": "blocked",
        "c2_locks": [("nrlock", "denied"), ("nwlock", "denied")],
    },
    # C1 RO + nrlock; C2 RO + nrlock both success during grace
    "TC-TSM-G-C11": {
        "desc": "C1 RO+nrlock; C2 RO+nrlock both succeed during grace (compatible)",
        "c1_mode": RO,
        "c1_lock": "nrlock",
        "c2_mode": RO,
        "c2_expect": "success",
        "c2_lock_during": "nrlock",
    },
    # C1 RO + nrlock; C2 RW blocked → after grace open; nwlock denied, nrlock success
    "TC-TSM-G-C12": {
        "desc": (
            "C1 RO+nrlock; C2 RW blocked at open, after grace open ok; "
            "nwlock denied then nrlock success"
        ),
        "c1_mode": RO,
        "c1_lock": "nrlock",
        "c2_mode": RW,
        "c2_expect": "blocked",
        "c2_locks": [("nwlock", "denied"), ("nrlock", "success")],
    },
    # --- Deleg export (delegations=rw): C13 write-deleg, C14/C15 read-deleg ---
    "TC-TSM-G-C13": {
        "desc": (
            "deleg type5: C1 WO+nwlock; C2 RW blocked; after grace recall; "
            "nrlock then nwlock denied"
        ),
        "use_deleg_export": True,
        "c1_mode": WO,
        "c1_lock": "nwlock",
        "c2_mode": RW,
        "c2_expect": "blocked",
        # After C2 open: recall → C1's client-local lock lands in TSM
        "after_open_lock_delta": 1,
        "after_open_deleg_delta": -1,  # recall 1→0
        "c2_locks": [("nrlock", "denied"), ("nwlock", "denied")],
    },
    "TC-TSM-G-C14": {
        "desc": (
            "deleg type4: C1 RO+nrlock; C2 RW blocked; after grace open ok; "
            "nwlock denied then nrlock success"
        ),
        "use_deleg_export": True,
        "c1_mode": RO,
        "c1_lock": "nrlock",
        "c2_mode": RW,
        "c2_expect": "blocked",
        # After C2 open: recall → C1's client-local lock lands in TSM
        "after_open_lock_delta": 1,
        "after_open_deleg_delta": -1,  # recall 1→0
        "c2_locks": [("nwlock", "denied"), ("nrlock", "success")],
    },
    "TC-TSM-G-C15": {
        "desc": (
            "deleg type4: C1 RO+nrlock; C2 RO+nrlock both succeed during grace "
            "(deleg 1→2)"
        ),
        "use_deleg_export": True,
        "c1_mode": RO,
        "c1_lock": "nrlock",
        "c2_mode": RO,
        "c2_expect": "success",
        "c2_lock_during": "nrlock",
    },
    # Pre-grace sticky records on wf0; C01-style conflict on wf1 during/after grace
    "TC-TSM-G-C16": {
        "desc": (
            "pre-grace C1 WO+nwlock on wf0; during grace C1 WO + C2 RO blocked on wf1; "
            "after grace open ok; pre-grace lock preserved"
        ),
        "pre_grace": {
            "c1_mode": WO,
            "c1_lock": "nwlock",
            "file_idx": PRE_FILE_IDX,
        },
        "c1_mode": WO,
        "c2_mode": RO,
        "c2_expect": "blocked",
    },
    "TC-TSM-G-C17": {
        "desc": (
            "pre-grace C1 WO+nwlock on wf0; during grace C1 RO + C2 RO succeed on wf1; "
            "pre-grace lock preserved"
        ),
        "pre_grace": {
            "c1_mode": WO,
            "c1_lock": "nwlock",
            "file_idx": PRE_FILE_IDX,
        },
        "c1_mode": RO,
        "c2_mode": RO,
        "c2_expect": "success",
    },
    "TC-TSM-G-C18": {
        "desc": (
            "pre-grace C1 WO+nwlock on wf0; during grace C1 WO + C2 RW blocked on wf1; "
            "after grace open ok; nrlock then nwlock denied; pre-grace lock preserved"
        ),
        "pre_grace": {
            "c1_mode": WO,
            "c1_lock": "nwlock",
            "file_idx": PRE_FILE_IDX,
        },
        "c1_mode": WO,
        "c2_mode": RW,
        "c2_expect": "blocked",
        "c2_locks": [("nrlock", "denied"), ("nwlock", "denied")],
    },
    "TC-TSM-G-C19": {
        "desc": (
            "pre-grace C1 RO+nrlock on wf0; during grace C1 WO + C2 RW blocked on wf1; "
            "after grace open ok; nwlock denied then nrlock success"
        ),
        "pre_grace": {
            "c1_mode": RO,
            "c1_lock": "nrlock",
            "file_idx": PRE_FILE_IDX,
        },
        "c1_mode": WO,
        "c2_mode": RW,
        "c2_expect": "blocked",
        "c2_locks": [("nwlock", "denied"), ("nrlock", "success")],
    },
    "TC-TSM-G-C20": {
        "desc": (
            "pre-grace C1 WO+nwlock on wf1; during grace C2 RO blocked on same file; "
            "after grace open ok; nrlock then nwlock denied"
        ),
        "pre_grace": {
            "c1_mode": WO,
            "c1_lock": "nwlock",
            "file_idx": WF_FILE_IDX,
        },
        "skip_c1_during": True,  # C1 already holds wf1 from pre-grace
        "c1_mode": WO,  # existing_sa for conflict logs
        "c2_mode": RO,
        "c2_expect": "blocked",
        "c2_locks": [("nrlock", "denied"), ("nwlock", "denied")],
    },
    "TC-TSM-G-C21": {
        "desc": (
            "deleg: pre-grace C1 WO+nwlock on wf0; during grace C1 WO+nwlock + C2 RW "
            "blocked on wf1; after recall; nrlock then nwlock denied"
        ),
        "use_deleg_export": True,
        "pre_grace": {
            "c1_mode": WO,
            "c1_lock": "nwlock",
            "file_idx": PRE_FILE_IDX,
        },
        "c1_mode": WO,
        "c1_lock": "nwlock",
        "c2_mode": RW,
        "c2_expect": "blocked",
        "after_open_lock_delta": 1,
        "after_open_deleg_delta": -1,
        "c2_locks": [("nrlock", "denied"), ("nwlock", "denied")],
    },
    "TC-TSM-G-C22": {
        "desc": (
            "pre-grace C1 WO+nwlock on wf0 + C2 RO+nrlock on wf2; during grace "
            "C1 WO + C2 RO blocked on wf1; after grace open ok; multi-client floor"
        ),
        "pre_grace": {
            "c1_mode": WO,
            "c1_lock": "nwlock",
            "file_idx": PRE_FILE_IDX,
        },
        "pre_grace_c2": {
            "c2_mode": RO,
            "c2_lock": "nrlock",
            "file_idx": PRE_C2_FILE_IDX,
        },
        "c1_mode": WO,
        "c2_mode": RO,
        "c2_expect": "blocked",
    },
}


def _file_base(mount):
    return f"{mount.rstrip('/')}/wf"


def _spare_file_base(mount):
    return f"{mount.rstrip('/')}/spare"


def _seed_wf_file(client, mount, indices=None):
    """Create wf{i}.txt for each index (needed for O_RDONLY/O_WRONLY/O_RDWR)."""
    if indices is None:
        indices = [WF_FILE_IDX]
    for i in indices:
        path = f"{_file_base(mount)}{i}.txt"
        client.exec_command(
            sudo=True,
            cmd=f"bash -c 'echo seed > {path}; chmod 666 {path}'",
            check_ec=False,
        )


def _workflow_peers(ctx):
    """Peers for TSM summary (exclude spare under partition)."""
    peers = list(ctx.peers) if ctx.peers else list(ctx.active[1:])
    if not ctx.spare_node:
        return peers
    return [n for n in peers if n.hostname != ctx.spare_node.hostname]


def _close_and_stop(sess, indexes=None, unlock_indexes=None):
    """Close held indexes (optional unlock first), then stop the session."""
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


def _mount_spare(ctx, nfs_version):
    """Create spare export + mount once; reuse across TCs if still mounted."""
    client = ctx.spare_client
    out, _ = client.exec_command(
        sudo=True,
        cmd=f"mountpoint -q {ctx.spare_mount} && echo ok",
        check_ec=False,
    )
    if "ok" in (out or ""):
        log.info("Spare already mounted at %s — skip export/subvolume", ctx.spare_mount)
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


def _start_spare_hold(ctx):
    """Open-hold spare0.txt via common_interactive (rwc)."""
    if ensure_interactive_binary(ctx.spare_client):
        return None
    base = _spare_file_base(ctx.spare_mount)
    sess = InteractiveSession(ctx.spare_client, base, tag="spare")
    if not sess.start():
        return None
    if sess.open_file(SPARE_FILE_IDX, "rwc", timeout=30) != "success":
        log.error("Spare open hold failed on %s%s.txt", base, SPARE_FILE_IDX)
        sess.stop()
        return None
    log.info(
        "Spare open hold active on %s (%s%s.txt)",
        ctx.spare_client.hostname,
        base,
        SPARE_FILE_IDX,
    )
    return sess


def _ensure_deleg_export(ctx, nfs_version):
    """Create primary-style export with delegations=rw; mount on workflow clients once."""
    if getattr(ctx, "_deleg_ready", False):
        return 0
    if not ctx.deleg_export or not ctx.deleg_mount:
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
    # Set export-level delegations=rw (ceph CLI on client; same as other grace cmds)
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


def _validate_conflict_logs(ctx, c1_mode, c2_mode, since, label):
    """Require Open conflict existing_sa/new_sa + NFS4ERR_GRACE on mount server."""
    existing_sa, new_sa = SHARE_ACCESS[c1_mode], SHARE_ACCESS[c2_mode]
    announce(
        f"[{label}] validate conflict existing_sa={existing_sa} "
        f"new_sa={new_sa} + NFS4ERR_GRACE"
    )
    node = ctx.server
    cid = get_nfs_container_id(node, nfs_name=ctx.nfs_name)
    if not cid:
        log.error("[%s] no NFS container on %s", label, node.hostname)
        return 1
    node_since = since.get(node.hostname) if isinstance(since, dict) else since
    since_arg = f' --since "{node_since}"' if node_since else ""
    out, _ = node.exec_command(
        sudo=True, cmd=f"podman logs{since_arg} {cid} 2>&1", check_ec=False
    )
    lines = (out or "").splitlines()
    for i, ln in enumerate(lines):
        m = CONFLICT_SA_RE.search(ln)
        if not m or int(m.group(1)) != existing_sa or int(m.group(2)) != new_sa:
            continue
        window = lines[i + 1 : i + 4]
        grace_ln = next((x for x in window if CONFLICT_GRACE_RE.search(x)), None)
        if grace_ln:
            log.info("[%s] conflict log ok:\n%s\n%s", label, ln, grace_ln)
            return 0
    log.error(
        "[%s] missing Open conflict existing_sa=%s new_sa=%s + NFS4ERR_GRACE",
        label,
        existing_sa,
        new_sa,
    )
    return 1


def _tsm_expect(
    ctx,
    baseline,
    label,
    since,
    must_match,
    open_delta=0,
    lock_delta=0,
    deleg_delta=None,
):
    """Check Node-id open/lock/(optional deleg) vs baseline+deltas.

    must_match=True  → wait until counts match
    must_match=False → fail if the bumped field(s) already match (blocked/denied)
    deleg_delta=None → do not assert deleg (C01–C12); int → assert base+delta
    """
    peers = _workflow_peers(ctx)
    node_id = ctx.server_node_id
    base_open = int((baseline or {}).get("open", 0))
    base_lock = int((baseline or {}).get("lock", 0))
    base_deleg = int((baseline or {}).get("deleg", 0))
    want_open = base_open + open_delta
    want_lock = base_lock + lock_delta
    want_deleg = None if deleg_delta is None else base_deleg + deleg_delta

    if must_match:
        announce(
            f"[{label}] validate TSM Node-id {node_id}",
            fmt_tsm(want_open, want_lock, want_deleg),
        )
        if (
            wait_peer_counts(
                peers,
                ctx.nfs_name,
                since,
                want_open,
                want_lock,
                label,
                expect_deleg=want_deleg,
                timeout=60,
                node_id=node_id,
            )
            is None
        ):
            return 1
        return 0

    announce(
        f"[{label}] TSM Node-id {node_id} must NOT match "
        f"{fmt_tsm(want_open if open_delta else base_open, want_lock if lock_delta else base_lock, want_deleg)}"
    )
    time.sleep(2)
    snap = peer_summary(peers, ctx.nfs_name, since=since, node_id=node_id)
    if not snap.get("seen"):
        log.info("[%s] no TSM summary yet — ok for blocked/denied", label)
        return 0
    if open_delta and int(snap.get("open", 0)) == want_open:
        log.error(
            "[%s] unexpected TSM open=%s on Node-id %s", label, want_open, node_id
        )
        return 1
    if lock_delta and int(snap.get("lock", 0)) == want_lock:
        log.error(
            "[%s] unexpected TSM lock=%s on Node-id %s", label, want_lock, node_id
        )
        return 1
    if deleg_delta is not None and int(snap.get("deleg", 0)) == want_deleg:
        log.error(
            "[%s] unexpected TSM deleg=%s on Node-id %s", label, want_deleg, node_id
        )
        return 1
    log.info(
        "[%s] no TSM bump match (open=%s lock=%s deleg=%s) — ok",
        label,
        snap.get("open"),
        snap.get("lock"),
        snap.get("deleg"),
    )
    return 0


def _normalize_c2_locks(spec):
    """Return [(kind, expect), ...] from c2_locks / legacy c2_lock + c2_lock_expect."""
    locks = spec.get("c2_locks")
    if locks:
        out = []
        default = spec.get("c2_lock_expect", "denied")
        for item in locks:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                out.append((item[0], item[1]))
            else:
                out.append((item, default))
        return out
    kind = spec.get("c2_lock")
    if kind:
        return [(kind, spec.get("c2_lock_expect", "denied"))]
    return []


def _run_c2_locks(ctx, c2_sess, peers, node_id, tag, locks):
    """Apply C2 lock steps after open is held. Return 0 ok, 1 fail."""
    for kind, expect in locks:
        label = f"{tag} C2 {kind} after open"
        announce(f"[{label}] expect={expect}")
        lock_since, _ = get_node_time([ctx.server] + peers)
        lock_base = peer_summary(peers, ctx.nfs_name, node_id=node_id)
        got = c2_sess.lock_file(WF_FILE_IDX, kind, timeout=15)
        if got != expect:
            log.error("[%s] want=%s got=%s", label, expect, got)
            return 1
        if expect == "denied":
            if _tsm_expect(
                ctx, lock_base, label, lock_since, False, lock_delta=1
            ):
                return 1
            log.info("[%s] → denied (TSM lock not bumped)", label)
        else:
            if _tsm_expect(
                ctx, lock_base, label, lock_since, True, lock_delta=1
            ):
                return 1
            log.info("[%s] → success (TSM lock +1)", label)
    return 0


def tc_conflict_generic(ctx, spec, nfs_version="4.2"):
    """One TC: optional pre-grace records; C1/C2 during grace; after-grace as needed."""
    tag = spec["id"]
    use_deleg = bool(spec.get("use_deleg_export"))
    pre_grace = spec.get("pre_grace")  # {c1_mode, c1_lock?, file_idx}
    pre_grace_c2 = spec.get("pre_grace_c2")  # {c2_mode, c2_lock?, file_idx}
    skip_c1_during = bool(spec.get("skip_c1_during"))
    c1_mode = spec.get("c1_mode", WO)
    c1_lock = spec.get("c1_lock")  # lock during grace (C10–C15); not pre-grace
    c2_mode = spec["c2_mode"]
    c2_expect = spec.get("c2_expect", "blocked")
    c2_lock_during = spec.get("c2_lock_during")
    c2_locks = _normalize_c2_locks(spec)
    after_open_deleg_delta = spec.get("after_open_deleg_delta")
    after_open_lock_delta = spec.get("after_open_lock_delta", 0)
    c1, c2 = ctx.client_a, ctx.client_b
    if not c2 or ctx.server_node_id is None:
        log.error("[%s] need C2 client and server_node_id", tag)
        return 1
    if ensure_interactive_binary(c1) or ensure_interactive_binary(c2):
        return 1

    if use_deleg:
        if _ensure_deleg_export(ctx, nfs_version):
            return 1
        mount = ctx.deleg_mount
    else:
        mount = ctx.mount

    seed_idxs = [WF_FILE_IDX]
    pre_idx = None
    pre_lock = None
    pre_mode = None
    if pre_grace:
        pre_idx = int(pre_grace.get("file_idx", PRE_FILE_IDX))
        pre_lock = pre_grace.get("c1_lock")
        pre_mode = pre_grace.get("c1_mode", WO)
        if pre_idx not in seed_idxs:
            seed_idxs.append(pre_idx)
    pre_c2_idx = None
    pre_c2_lock = None
    pre_c2_mode = None
    if pre_grace_c2:
        pre_c2_idx = int(pre_grace_c2.get("file_idx", PRE_C2_FILE_IDX))
        pre_c2_lock = pre_grace_c2.get("c2_lock")
        pre_c2_mode = pre_grace_c2.get("c2_mode", RO)
        if pre_c2_idx not in seed_idxs:
            seed_idxs.append(pre_c2_idx)
    _seed_wf_file(c1, mount, indices=seed_idxs)
    time.sleep(3 if use_deleg else 1)
    if _mount_spare(ctx, nfs_version):
        return 1

    spare_sess = _start_spare_hold(ctx)
    if not spare_sess:
        return 1
    ctx._spare_session = spare_sess

    c1_sess = None
    c2_sess = None
    c2_held_lock = False
    c1_close_idxs = [WF_FILE_IDX]
    c1_unlock_idxs = []
    c2_close_idxs = [WF_FILE_IDX]
    c2_unlock_idxs = []
    # Share-access for conflict logs: pre-grace open when C1 skips during-grace open
    conflict_existing_mode = pre_mode if (skip_c1_during and pre_mode) else c1_mode
    try:
        peers = _workflow_peers(ctx)
        if not peers:
            log.error("[%s] need ≥1 peer for TSM summary", tag)
            return 1
        node_id = ctx.server_node_id
        base = _file_base(mount)

        # --- Optional pre-grace sticky records (C1) ---
        if pre_grace:
            c1_sess = InteractiveSession(c1, base, tag="c1")
            if not c1_sess.start():
                return 1
            if pre_idx not in c1_close_idxs:
                c1_close_idxs.insert(0, pre_idx)
            label = f"{tag} C1 pre-grace {pre_mode}" + (
                f"+{pre_lock}" if pre_lock else ""
            )
            announce(f"[{label}] open expect=success (before grace)")
            baseline = peer_summary(peers, ctx.nfs_name, node_id=node_id)
            open_since, _ = get_node_time(peers)
            if c1_sess.open_file(pre_idx, pre_mode, timeout=30) != "success":
                log.error("[%s] pre-grace open failed", label)
                return 1
            if pre_lock:
                announce(f"[{label}] {pre_lock} expect=success")
                if c1_sess.lock_file(pre_idx, pre_lock, timeout=15) != "success":
                    log.error("[%s] pre-grace %s failed", label, pre_lock)
                    return 1
                c1_unlock_idxs.append(pre_idx)
                if use_deleg:
                    # Write-deleg: lock stays client-local until recall
                    if _tsm_expect(
                        ctx,
                        baseline,
                        label,
                        open_since,
                        True,
                        open_delta=1,
                        lock_delta=0,
                        deleg_delta=1,
                    ):
                        return 1
                elif _tsm_expect(
                    ctx, baseline, label, open_since, True, open_delta=1, lock_delta=1
                ):
                    return 1
            elif _tsm_expect(ctx, baseline, label, open_since, True, open_delta=1):
                return 1
            log.info("[%s] → pre-grace records ok (held through grace)", label)

        # --- Optional pre-grace sticky records (C2 / multi-client) ---
        if pre_grace_c2:
            c2_sess = InteractiveSession(c2, base, tag="c2pre")
            if not c2_sess.start():
                return 1
            if pre_c2_idx not in c2_close_idxs:
                c2_close_idxs.insert(0, pre_c2_idx)
            label = f"{tag} C2 pre-grace {pre_c2_mode}" + (
                f"+{pre_c2_lock}" if pre_c2_lock else ""
            )
            announce(f"[{label}] open expect=success (before grace)")
            baseline = peer_summary(peers, ctx.nfs_name, node_id=node_id)
            open_since, _ = get_node_time(peers)
            if c2_sess.open_file(pre_c2_idx, pre_c2_mode, timeout=30) != "success":
                log.error("[%s] C2 pre-grace open failed", label)
                return 1
            if pre_c2_lock:
                announce(f"[{label}] {pre_c2_lock} expect=success")
                if c2_sess.lock_file(pre_c2_idx, pre_c2_lock, timeout=15) != "success":
                    log.error("[%s] C2 pre-grace %s failed", label, pre_c2_lock)
                    return 1
                c2_unlock_idxs.append(pre_c2_idx)
                c2_held_lock = True
                if _tsm_expect(
                    ctx, baseline, label, open_since, True, open_delta=1, lock_delta=1
                ):
                    return 1
            elif _tsm_expect(ctx, baseline, label, open_since, True, open_delta=1):
                return 1
            log.info("[%s] → C2 pre-grace records ok (held through grace)", label)

        announce(f"[{tag}] hold cluster grace (spare + iptables -I)")
        rc, grace_since = hold_cluster_grace(ctx, spare_sess)
        if rc:
            return 1

        if not c1_sess:
            c1_sess = InteractiveSession(c1, base, tag="c1")
            if not c1_sess.start():
                return 1

        # --- C1 during grace (skipped when pre-grace already holds conflict file) ---
        if not skip_c1_during:
            label = f"{tag} C1 during {c1_mode}" + (f"+{c1_lock}" if c1_lock else "")
            announce(f"[{label}] open expect=success")
            baseline = peer_summary(peers, ctx.nfs_name, node_id=node_id)
            open_since, _ = get_node_time(peers)
            if c1_sess.open_file(WF_FILE_IDX, c1_mode, timeout=30) != "success":
                log.error("[%s] C1 open failed", label)
                return 1
            if c1_lock:
                announce(f"[{label}] {c1_lock} expect=success")
                if c1_sess.lock_file(WF_FILE_IDX, c1_lock, timeout=15) != "success":
                    log.error("[%s] C1 %s failed", label, c1_lock)
                    return 1
                c1_unlock_idxs.append(WF_FILE_IDX)
                if use_deleg:
                    if _tsm_expect(
                        ctx,
                        baseline,
                        label,
                        open_since,
                        True,
                        open_delta=1,
                        lock_delta=0,
                        deleg_delta=1,
                    ):
                        return 1
                elif _tsm_expect(
                    ctx, baseline, label, open_since, True, open_delta=1, lock_delta=1
                ):
                    return 1
            else:
                # With pre-grace lock held: open+1, lock unchanged (floor preserved)
                if _tsm_expect(
                    ctx, baseline, label, open_since, True, open_delta=1, lock_delta=0
                ):
                    return 1
            log.info("[%s] → success (TSM Node-id %s ok)", label, node_id)
        else:
            announce(
                f"[{tag}] skip C1 during-grace open "
                f"(pre-grace holds index {pre_idx})"
            )

        # --- C2 during grace ---
        label = f"{tag} C2 during {c2_mode}"
        announce(f"[{label}] open expect={c2_expect}")
        open_since, _ = get_node_time([ctx.server] + peers)
        baseline = peer_summary(peers, ctx.nfs_name, node_id=node_id)
        if not c2_sess:
            c2_sess = InteractiveSession(
                c2, base, tag=f"probe{int(time.time()) % 100000}"
            )
            if not c2_sess.start():
                return 1
        timeout = 8 if c2_expect == "blocked" else 30
        got = c2_sess.open_file(WF_FILE_IDX, c2_mode, timeout=timeout)
        if got != c2_expect:
            log.error("[%s] open want=%s got=%s", label, c2_expect, got)
            return 1

        if c2_expect == "blocked":
            if _validate_conflict_logs(
                ctx, conflict_existing_mode, c2_mode, open_since, label
            ):
                return 1
            if _tsm_expect(
                ctx, baseline, label, open_since, False, open_delta=1
            ):
                return 1
            # Pre-grace floor still present
            if pre_grace or pre_grace_c2:
                if use_deleg:
                    if int(baseline.get("open", 0)) < 1:
                        log.error("[%s] pre-grace open missing during blocked open", label)
                        return 1
                    if int(baseline.get("deleg", 0)) < 1:
                        log.error(
                            "[%s] pre-grace deleg missing during blocked open", label
                        )
                        return 1
                else:
                    min_open = 2 if pre_grace_c2 else 1
                    if int(baseline.get("open", 0)) < min_open:
                        log.error(
                            "[%s] pre-grace open floor missing "
                            "(want≥%s got=%s)",
                            label,
                            min_open,
                            baseline.get("open"),
                        )
                        return 1
                    if int(baseline.get("lock", 0)) < 1:
                        log.error(
                            "[%s] pre-grace lock missing during blocked open", label
                        )
                        return 1
            log.info("[%s] → blocked (session kept for after-grace)", label)

            after_since, _ = get_node_time([ctx.server] + peers)

            announce(f"[{tag}] unblock spare TCP (end grace hold)")
            unblock_cluster_grace(ctx)

            announce(f"[{tag}] wait NOT IN GRACE")
            if wait_grace_exit(ctx, grace_since, timeout=150):
                log.error("[%s] grace did not end in time", tag)
                return 1

            label = f"{tag} C2 after {c2_mode} (same open)"
            announce(f"[{label}] wait hanging open; TSM open +1 (no fresh open)")
            if c2_sess.wait_opened(WF_FILE_IDX, timeout=90) != "success":
                log.error("[%s] hanging open did not complete", label)
                return 1
            if _tsm_expect(
                ctx,
                baseline,
                label,
                after_since,
                True,
                open_delta=1,
                lock_delta=after_open_lock_delta,
                deleg_delta=after_open_deleg_delta,
            ):
                return 1
            log.info("[%s] → open success (TSM Node-id %s +1)", label, node_id)
        else:
            if c2_lock_during:
                announce(f"[{label}] {c2_lock_during} expect=success")
                if c2_sess.lock_file(WF_FILE_IDX, c2_lock_during, timeout=15) != "success":
                    log.error("[%s] C2 %s failed", label, c2_lock_during)
                    return 1
                c2_held_lock = True
                c2_unlock_idxs.append(WF_FILE_IDX)
                if use_deleg:
                    if _tsm_expect(
                        ctx,
                        baseline,
                        label,
                        open_since,
                        True,
                        open_delta=1,
                        lock_delta=0,
                        deleg_delta=1,
                    ):
                        return 1
                elif _tsm_expect(
                    ctx,
                    baseline,
                    label,
                    open_since,
                    True,
                    open_delta=1,
                    lock_delta=1,
                ):
                    return 1
            elif _tsm_expect(ctx, baseline, label, open_since, True, open_delta=1):
                return 1
            log.info("[%s] → success (TSM Node-id %s ok)", label, node_id)

            announce(f"[{tag}] unblock spare TCP (end grace hold)")
            unblock_cluster_grace(ctx)
            announce(f"[{tag}] wait NOT IN GRACE")
            if wait_grace_exit(ctx, grace_since, timeout=150):
                log.error("[%s] grace did not end in time", tag)
                return 1

        if c2_locks and _run_c2_locks(ctx, c2_sess, peers, node_id, tag, c2_locks):
            return 1
        if any(exp == "success" for _, exp in c2_locks):
            c2_held_lock = True
            if WF_FILE_IDX not in c2_unlock_idxs:
                c2_unlock_idxs.append(WF_FILE_IDX)

        log.info("[%s] PASSED", tag)
        return 0
    finally:
        unlock_c2 = list(c2_unlock_idxs) if c2_held_lock or c2_unlock_idxs else []
        _close_and_stop(
            c2_sess,
            indexes=c2_close_idxs,
            unlock_indexes=unlock_c2,
        )
        _close_and_stop(
            c1_sess,
            indexes=c1_close_idxs,
            unlock_indexes=c1_unlock_idxs,
        )
        release_cluster_grace(ctx)


def _log_tc_overview(ctx):
    primary = ctx.server.hostname if ctx.server else "N/A"
    spare = ctx.spare_node.hostname if ctx.spare_node else "N/A"
    ids = ", ".join(
        f"{h}={nid}" for h, nid in sorted(ctx.tsm_node_ids.items())
    ) or "N/A"
    deleg = getattr(ctx, "deleg_export", None) or "N/A"
    log.info(
        "\n========== OVERVIEW =========================\n"
        "Spare node - %s\n"
        "Spare Client - %s\n"
        "Spare Export - %s\n"
        "Deleg Export - %s\n"
        "Client-1/2 Mounts to - %s (TSM Node-id %s)\n"
        "TSM Node-id map - %s\n"
        "============ OVERVIEW =======================",
        spare,
        ctx.spare_client.hostname if ctx.spare_client else "N/A",
        ctx.spare_export or "N/A",
        deleg,
        primary,
        ctx.server_node_id,
        ids,
    )


def run(ceph_cluster, **kw):
    """Deploy 4-node TSM cluster, run registered grace conflict WORKFLOWS."""
    config = kw.get("config") or {}
    selected = config.get("workflows")
    nfs_version = str(config.get("nfs_version", "4.2"))
    nfs_count = int(config.get("nfs_count", DEFAULT_NFS_COUNT))

    nfs_nodes = sorted(ceph_cluster.get_nodes("nfs"), key=lambda n: n.hostname)
    clients = ceph_cluster.get_nodes("client")
    installer = ceph_cluster.get_nodes("installer")[0]

    if len(nfs_nodes) < nfs_count:
        log.error("Need ≥%s NFS nodes (have %s)", nfs_count, len(nfs_nodes))
        return 1
    if len(clients) < MIN_CLIENTS:
        log.error("Need ≥%s clients (have %s)", MIN_CLIENTS, len(clients))
        return 1

    nodes = nfs_nodes[:nfs_count]
    use_clients = clients[:MIN_CLIENTS]
    name = "tsmg-grace"
    nfs_name = f"cephfs-nfs-{name}"
    export = f"/export_{name}"
    mount = f"/mnt/nfs_{name}"
    spare_export = f"/export_{name}_spare"
    spare_mount = f"/mnt/nfs_{name}_spare"
    deleg_export = f"/export_{name}_deleg"
    deleg_mount = f"/mnt/nfs_{name}_deleg"
    results = {}
    ctx = None

    try:
        result = deploy_step(
            ceph_cluster,
            installer,
            use_clients[0],
            nodes,
            {"nfs_count": nfs_count, "tsm_port": TSM_PORT},
            nfs_name,
            name,
        )
        if result is None:
            raise RuntimeError("deploy failed")
        _, active, nfs_port, _ = result
        if len(active) < nfs_count:
            raise RuntimeError(
                f"Expected {nfs_count} active NFS daemons, got {len(active)}"
            )

        announce("Collect TSM Node-ids from podman logs (Ganesha ID)")
        tsm_node_ids = collect_tsm_node_ids(active, nfs_name)
        if len(tsm_node_ids) < len(active):
            missing = [n.hostname for n in active if n.hostname not in tsm_node_ids]
            raise RuntimeError(f"Missing TSM Node-id for: {missing}")

        if _mount_clients(
            use_clients[:-1],
            nfs_name,
            export,
            mount,
            nfs_port,
            active[0].hostname,
            nfs_version=nfs_version,
        ):
            raise RuntimeError("primary mount failed")

        ctx = GraceCtx(
            clients=use_clients[:-1],
            active=active,
            peers=active[1:],
            server=active[0],
            nfs_name=nfs_name,
            export=export,
            mount=mount,
            nfs_port=nfs_port,
            spare_node=active[-1],
            spare_client=use_clients[-1],
            spare_export=spare_export,
            spare_mount=spare_mount,
            tsm_port=TSM_PORT,
            tsm_node_ids=tsm_node_ids,
        )
        ctx.deleg_export = deleg_export
        ctx.deleg_mount = deleg_mount
        ctx._deleg_ready = False

        cases = selected or list(WORKFLOWS.keys())
        _, coredump_since = get_node_time(nodes)
        for i, tc_id in enumerate(cases, 1):
            spec = WORKFLOWS.get(tc_id)
            if not spec:
                log.error("Unknown workflow %s", tc_id)
                results[tc_id] = "failed"
                continue
            log.info(
                "\n==============================\n"
                "Test %s: %s: %s\n"
                "==============================",
                i,
                tc_id,
                spec["desc"],
            )
            _log_tc_overview(ctx)
            announce("Do workflow [%s] — %s" % (tc_id, spec["desc"]))
            try:
                rc = tc_conflict_generic(
                    ctx, dict(spec, id=tc_id), nfs_version=nfs_version
                )
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
        if not results:
            results["suite"] = "failed"
    finally:
        if ctx:
            release_cluster_grace(ctx)
            if ctx.spare_client and ctx.spare_mount:
                ctx.spare_client.exec_command(
                    sudo=True,
                    cmd=f"umount -l {ctx.spare_mount} 2>/dev/null",
                    check_ec=False,
                )
                try:
                    Ceph(ctx.spare_client).nfs.export.delete(
                        ctx.nfs_name, ctx.spare_export
                    )
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
                    Ceph(ctx.client_a).nfs.export.delete(
                        ctx.nfs_name, ctx.deleg_export
                    )
                except Exception as exc:
                    log.warning("deleg export delete: %s", exc)
        # Unmount all clients before NFS cluster delete (safe_cleanup only
        # umounts use_clients[0]).
        for client in use_clients:
            client.exec_command(
                sudo=True,
                cmd=f"umount -l {mount} 2>/dev/null",
                check_ec=False,
            )
        safe_cleanup(use_clients[0], mount, nfs_name, export, nodes)

    return log_workflow_summary(results, title="TSM GRACE IO SUMMARY")
