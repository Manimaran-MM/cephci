"""NFS TSM grace-period IO conflict workflows.

Grace hold: spare open + iptables -I on spare client + spare NFS restart
→ ~90s cluster grace → C1/C2 conflict checks → unblock → after-grace TSM.

TC-C01..C03: C1 WRITE_ONLY during grace; one C2 mode blocked (hangs), then
same open completes after grace (TSM open +1, no fresh open).
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
SPARE_FILE_IDX = 0
WF_FILE_IDX = 1

WO, RO, RW = "WRITE_ONLY", "READ_ONLY", "READ_WRITE"
SHARE_ACCESS = {RO: 1, WO: 2, RW: 3}

CONFLICT_SA_RE = re.compile(
    r"Open conflict existing_sa=(\d+) new_sa=(\d+)", re.I
)
CONFLICT_GRACE_RE = re.compile(
    r"Conflicting open\.\s*Return NFS4ERR_GRACE", re.I
)

# Each TC: C1 WO success during grace; one C2 mode blocked then completes after.
WORKFLOWS = {
    "TC-TSM-G-C01": {
        "desc": "C1 WRITE_ONLY; C2 READ_ONLY blocked then completes after grace",
        "c2_mode": RO,
    },
    "TC-TSM-G-C02": {
        "desc": "C1 WRITE_ONLY; C2 WRITE_ONLY blocked then completes after grace",
        "c2_mode": WO,
    },
    "TC-TSM-G-C03": {
        "desc": "C1 WRITE_ONLY; C2 READ_WRITE blocked then completes after grace",
        "c2_mode": RW,
    },
}


def _file_base(mount):
    return f"{mount.rstrip('/')}/wf"


def _spare_file_base(mount):
    return f"{mount.rstrip('/')}/spare"


def _seed_wf_file(client, mount):
    path = f"{_file_base(mount)}{WF_FILE_IDX}.txt"
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


def _close_and_stop(sess, index=None):
    if not sess:
        return
    try:
        if index is not None:
            sess.send(f"close {index}")
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


def _tsm_expect_open(ctx, baseline, want_delta, label, since, must_match):
    """Check Node-id open count vs baseline+delta.

    must_match=True  → wait until open == baseline+delta (success path)
    must_match=False → fail if open == baseline+delta (blocked path)
    """
    peers = _workflow_peers(ctx)
    node_id = ctx.server_node_id
    base_open = int((baseline or {}).get("open", 0))
    base_lock = int((baseline or {}).get("lock", 0))
    want = base_open + want_delta

    if must_match:
        announce(
            f"[{label}] validate TSM Node-id {node_id}",
            fmt_tsm(want, base_lock),
        )
        if (
            wait_peer_counts(
                peers,
                ctx.nfs_name,
                since,
                want,
                base_lock,
                label,
                timeout=60,
                node_id=node_id,
            )
            is None
        ):
            return 1
        return 0

    announce(f"[{label}] blocked: TSM Node-id {node_id} must NOT match open={want}")
    time.sleep(2)
    snap = peer_summary(peers, ctx.nfs_name, since=since, node_id=node_id)
    if snap.get("seen") and int(snap.get("open", 0)) == want:
        log.error(
            "[%s] unexpected TSM open=%s on Node-id %s for blocked open",
            label,
            want,
            node_id,
        )
        return 1
    log.info(
        "[%s] no TSM open +1 match (seen=%s) — ok for blocked",
        label,
        snap.get("seen"),
    )
    return 0


def tc_conflict_generic(ctx, spec, nfs_version="4.2"):
    """One TC: C1 WO during grace; C2 mode blocked then completes after grace."""
    tag = spec["id"]
    c2_mode = spec["c2_mode"]
    c1, c2 = ctx.client_a, ctx.client_b
    if not c2 or ctx.server_node_id is None:
        log.error("[%s] need C2 client and server_node_id", tag)
        return 1
    if ensure_interactive_binary(c1) or ensure_interactive_binary(c2):
        return 1

    _seed_wf_file(c1, ctx.mount)
    time.sleep(1)
    if _mount_spare(ctx, nfs_version):
        return 1

    spare_sess = _start_spare_hold(ctx)
    if not spare_sess:
        return 1
    # Ensure release_cluster_grace can close spare even if hold_cluster_grace fails early
    ctx._spare_session = spare_sess

    c1_sess = None
    c2_sess = None
    try:
        announce(f"[{tag}] hold cluster grace (spare + iptables -I)")
        rc, grace_since = hold_cluster_grace(ctx, spare_sess)
        if rc:
            return 1

        peers = _workflow_peers(ctx)
        if not peers:
            log.error("[%s] need ≥1 peer for TSM summary", tag)
            return 1

        base = _file_base(ctx.mount)
        c1_sess = InteractiveSession(c1, base, tag="c1")
        if not c1_sess.start():
            return 1

        node_id = ctx.server_node_id

        # --- C1 WRITE_ONLY during grace ---
        label = f"{tag} C1 during {WO}"
        announce(f"[{label}] open expect=success")
        baseline = peer_summary(peers, ctx.nfs_name, node_id=node_id)
        open_since, _ = get_node_time(peers)
        if c1_sess.open_file(WF_FILE_IDX, WO, timeout=30) != "success":
            log.error("[%s] C1 open failed", label)
            return 1
        if _tsm_expect_open(ctx, baseline, 1, label, open_since, must_match=True):
            return 1
        log.info("[%s] → success (TSM Node-id %s ok)", label, node_id)

        # --- C2 during grace (blocked; keep session hanging) ---
        label = f"{tag} C2 during {c2_mode}"
        announce(f"[{label}] open expect=blocked")
        open_since, _ = get_node_time([ctx.server] + peers)
        baseline = peer_summary(peers, ctx.nfs_name, node_id=node_id)
        c2_sess = InteractiveSession(
            c2, base, tag=f"probe{int(time.time()) % 100000}"
        )
        if not c2_sess.start():
            return 1
        if c2_sess.open_file(WF_FILE_IDX, c2_mode, timeout=8) != "blocked":
            log.error("[%s] expected blocked", label)
            return 1
        if _validate_conflict_logs(ctx, WO, c2_mode, open_since, label):
            return 1
        if _tsm_expect_open(ctx, baseline, 1, label, open_since, must_match=False):
            return 1
        log.info("[%s] → blocked (session kept for after-grace)", label)

        # Stamp before unblock so --since includes open+1 logged at grace exit
        after_since, _ = get_node_time([ctx.server] + peers)

        announce(f"[{tag}] unblock spare TCP (end grace hold)")
        unblock_cluster_grace(ctx)

        announce(f"[{tag}] wait NOT IN GRACE")
        if wait_grace_exit(ctx, grace_since, timeout=150):
            log.error("[%s] grace did not end in time", tag)
            return 1

        # --- After grace: same hanging open completes; TSM +1 ---
        label = f"{tag} C2 after {c2_mode} (same open)"
        announce(f"[{label}] wait hanging open; TSM +1 (no fresh open)")
        if c2_sess.wait_opened(WF_FILE_IDX, timeout=90) != "success":
            log.error("[%s] hanging open did not complete", label)
            return 1
        if _tsm_expect_open(ctx, baseline, 1, label, after_since, must_match=True):
            return 1
        log.info("[%s] → success (TSM Node-id %s +1)", label, node_id)

        log.info("[%s] PASSED", tag)
        return 0
    finally:
        _close_and_stop(c2_sess, WF_FILE_IDX)
        _close_and_stop(c1_sess, WF_FILE_IDX)
        release_cluster_grace(ctx)


def _log_tc_overview(ctx):
    primary = ctx.server.hostname if ctx.server else "N/A"
    spare = ctx.spare_node.hostname if ctx.spare_node else "N/A"
    ids = ", ".join(
        f"{h}={nid}" for h, nid in sorted(ctx.tsm_node_ids.items())
    ) or "N/A"
    log.info(
        "\n========== OVERVIEW =========================\n"
        "Spare node - %s\n"
        "Spare Client - %s\n"
        "Spare Export - %s\n"
        "Client-1/2 Mounts to - %s (TSM Node-id %s)\n"
        "TSM Node-id map - %s\n"
        "============ OVERVIEW =======================",
        spare,
        ctx.spare_client.hostname if ctx.spare_client else "N/A",
        ctx.spare_export or "N/A",
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
        safe_cleanup(use_clients[0], mount, nfs_name, export, nodes)
        for client in use_clients[1:]:
            client.exec_command(
                sudo=True,
                cmd=f"umount -l {mount} 2>/dev/null",
                check_ec=False,
            )

    return log_workflow_summary(results, title="TSM GRACE IO SUMMARY")
