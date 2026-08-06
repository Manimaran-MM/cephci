"""NFS TSM + NFSv4 delegation lifecycle workflow.

Single workflow (TC-TSM-DELEG-01): deploy a 2-daemon TSM cluster once, enable
export-level rw delegations via the shared NFS delegation helpers, then walk
grant → conflict/recall → return → touch → delegations=none while asserting
peer ``Tsm record summary`` open/lock/deleg counters (same signal as
test_nfs_tsm_record_validation.py).
"""

import re
import time

from cli.ceph.ceph import Ceph
from cli.cephadm.cephadm import CephAdm
from cli.exceptions import OperationFailedError
from cli.utilities.filesys import Mount
from nfs_delegation_operations import (
    capture_delegation_ganesha_log_phase,
    delegation_timing_from_config,
    enable_cluster_delegation_and_debug_logging,
    ensure_ceph_conf_and_admin_keyring_on_hosts,
    hold_delegation_open,
    kill_delegation_holds,
    parse_nfs4_open_delegation_types,
    release_delegation_hold_gracefully,
    restore_delegation_ganesha_templates,
    skip_delegation_tests_unless_supported,
    start_ganesha_delegation_tailf_follow,
    stop_ganesha_delegation_tailf_follow,
    truncate_ganesha_container_log,
    update_export_delegation,
    validate_delegation_grant_capture,
    validate_delegation_recall_ganesha_capture,
    wait_for_delegation_path,
    wait_for_delegreturn_in_ganesha_capture,
    write_delegation_file,
)
from nfs_operations import get_ganesha_info_from_container
from tests.nfs.lib.common_lib import get_nfs_container_id, get_node_time
from tests.nfs.lib.multi_active.config import NfsMultiActiveConfig
from tests.nfs.lib.multi_active.delegation import NfsMultiActiveDelegation
from tests.nfs.tsm.test_nfs_tsm_basic import deploy_step, safe_cleanup
from utility.log import Log

log = Log(__name__)

SUMMARY_RE = re.compile(
    r"Tsm record summary total=(\d+) open=(\d+) lock=(\d+) deleg=(\d+)", re.I
)
POLL_TIMEOUT = 90
POLL_INTERVAL = 3
NFS_PORT = 12052
TSM_PORT = 36372

HOLD_FILE = "tsm_deleg_hold.txt"
TOUCH_FILE = "tsm_deleg_touch.txt"
NONE_FILE = "tsm_deleg_none.txt"


def _peer_summary(peers, nfs_name, since=None):
    """Parse last matching peer TSM summary line across peers."""
    counts = {"total": 0, "open": 0, "lock": 0, "deleg": 0, "seen": False}
    for node in peers:
        cid = get_nfs_container_id(node, nfs_name=nfs_name)
        if not cid:
            continue
        node_since = since.get(node.hostname) if isinstance(since, dict) else since
        since_arg = f' --since "{node_since}"' if node_since else ""
        out, _ = node.exec_command(
            sudo=True, cmd=f"podman logs{since_arg} {cid} 2>&1", check_ec=False
        )
        lines = [ln for ln in (out or "").splitlines() if SUMMARY_RE.search(ln)]
        log.info(
            "TSM record summary on %s:\n%s",
            node.hostname,
            "\n".join(lines[-3:]) if lines else "<none>",
        )
        if not lines:
            continue
        m = SUMMARY_RE.search(lines[-1])
        if not m:
            continue
        counts["seen"] = True
        counts["total"] = max(counts["total"], int(m.group(1)))
        counts["open"] = max(counts["open"], int(m.group(2)))
        counts["lock"] = max(counts["lock"], int(m.group(3)))
        counts["deleg"] = max(counts["deleg"], int(m.group(4)))
    return counts


def _wait_counts(
    peers,
    nfs_name,
    since,
    expect_open,
    expect_lock,
    expect_deleg,
    label,
):
    """Poll peer summaries until open/lock/deleg match. Return 0 ok, 1 timeout."""
    deadline = time.time() + POLL_TIMEOUT
    last = None
    while time.time() < deadline:
        last = _peer_summary(peers, nfs_name, since=since)
        if (
            last.get("seen")
            and last["open"] == expect_open
            and last["lock"] == expect_lock
            and last["deleg"] == expect_deleg
        ):
            log.info(
                "[%s] peer summary ok (open=%s lock=%s deleg=%s)",
                label,
                expect_open,
                expect_lock,
                expect_deleg,
            )
            return 0
        time.sleep(POLL_INTERVAL)
    log.error(
        "[%s] peer summary timeout: want open=%s lock=%s deleg=%s last=%s",
        label,
        expect_open,
        expect_lock,
        expect_deleg,
        last,
    )
    return 1


def _mount_clients(clients, nfs_name, export, mount, nfs_port, server, nfs_version):
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


def _ganesha_on_server(installer, nfs_name, server):
    _, info = get_ganesha_info_from_container(installer, nfs_name, server)
    container_id = (info or {}).get("container_id")
    if not container_id:
        raise OperationFailedError(
            "No Ganesha container for nfs.%s on %s" % (nfs_name, server.hostname)
        )
    return container_id


def _log_summary(results):
    passed = [n for n, s in results.items() if s == "passed"]
    failed = [n for n, s in results.items() if s == "failed"]
    skipped = [n for n, s in results.items() if s == "skipped"]
    log.info(
        "\n%s\nTSM DELEGATION WORKFLOW SUMMARY\n%s\n%s\n%s\n%s",
        "=" * 60,
        "=" * 60,
        "\n".join(f"  {n:<36} {s.upper()}" for n, s in results.items()),
        "-" * 60
        + f"\n  Total: {len(results)}  Passed: {len(passed)}  "
        f"Failed: {len(failed)}  Skipped: {len(skipped)}",
        "=" * 60,
    )
    return 1 if failed else 0


def _step(results, name, fn):
    """Run one workflow step; record passed/failed. Return True if passed."""
    log.info(
        "\n==============================\n"
        "Step: %s\n"
        "==============================",
        name,
    )
    try:
        fn()
        results[name] = "passed"
        log.info("[%s] PASSED", name)
        return True
    except Exception as exc:
        log.error("[%s] FAILED: %s", name, exc)
        results[name] = "failed"
        return False


def run(ceph_cluster, **kw):
    """TC-TSM-DELEG-01: TSM peer open/lock/deleg counters across one delegation workflow."""
    config = kw.get("config") or {}
    if skip_delegation_tests_unless_supported(config):
        return 0

    nfs_version = str(config.get("nfs_version", "4.2"))
    nfs_nodes = sorted(ceph_cluster.get_nodes("nfs"), key=lambda n: n.hostname)
    clients = ceph_cluster.get_nodes("client")
    installer = ceph_cluster.get_nodes("installer")[0]
    if len(nfs_nodes) < 2 or len(clients) < 2:
        log.error("Need ≥2 NFS nodes and ≥2 clients")
        return 1

    timing = delegation_timing_from_config(config)
    hold_s = timing.hold_seconds
    ready_s = timing.hold_ready_seconds
    settle_s = timing.log_settle_seconds
    exit_wait = timing.exit_wait_seconds
    return_wait = timing.return_wait_seconds
    path_wait_retries = timing.path_wait_retries
    redeploy_wait = int(config.get("redeploy_wait", 30))
    service_wait = int(config.get("service_wait_timeout", 300))

    nodes = nfs_nodes[:2]
    use_clients = clients[:2]
    client_a, client_b = use_clients[0], use_clients[1]
    name = "tsmr-deleg"
    nfs_name = f"cephfs-nfs-{name}"
    export = f"/export_{name}"
    mount = f"/mnt/nfs_{name}"
    hold_path = f"{mount}/{HOLD_FILE}"
    touch_path = f"{mount}/{TOUCH_FILE}"
    none_path = f"{mount}/{NONE_FILE}"

    results = {}
    peers = nodes[1:]
    server = nodes[0]
    container_id = None
    nfs_cmd_host = nodes[0]
    cephadm = CephAdm(installer).ceph
    delegation_template_backup = logging_template_backup = False
    hold_duration = max(int(hold_s), int(ready_s) + int(settle_s) + 30)
    base_open = base_lock = base_deleg = 0
    since = None
    rc = 1

    ensure_ceph_conf_and_admin_keyring_on_hosts(installer, nfs_nodes)

    try:
        result = deploy_step(
            ceph_cluster,
            installer,
            use_clients[0],
            nodes,
            {"nfs_count": 2, "nfs_port": NFS_PORT, "tsm_port": TSM_PORT},
            nfs_name,
            name,
        )
        if result is None:
            results["deploy"] = "failed"
            return _log_summary(results)

        _, active, nfs_port, _ = result
        server, peers = active[0], active[1:]
        nfs_cmd_host = server
        results["deploy"] = "passed"

        delegation_template_backup, logging_template_backup = (
            enable_cluster_delegation_and_debug_logging(
                nfs_cmd_host,
                cephadm,
                [nfs_name],
                installer,
                redeploy_wait,
                service_wait,
            )
        )
        results["enable_delegations_debug"] = "passed"

        if _mount_clients(
            use_clients,
            nfs_name,
            export,
            mount,
            nfs_port,
            server.hostname,
            nfs_version=nfs_version,
        ):
            results["mount"] = "failed"
            return _log_summary(results)
        results["mount"] = "passed"

        NfsMultiActiveDelegation.enable_rw_export(nfs_cmd_host, nfs_name, export)
        results["export_delegations_rw"] = "passed"

        container_id = _ganesha_on_server(installer, nfs_name, server)
        since, _ = get_node_time(peers)
        baseline = _peer_summary(peers, nfs_name, since=since)
        base_open, base_lock, base_deleg = (
            baseline["open"],
            baseline["lock"],
            baseline["deleg"],
        )
        log.info(
            "Initial baseline: open=%s lock=%s deleg=%s",
            base_open,
            base_lock,
            base_deleg,
        )

        # ------------------------------------------------------------------
        # Step 1: WRITE delegation grant while OPEN held
        # Expect: Ganesha type 5; peer open+1, deleg+1
        # ------------------------------------------------------------------
        def step_grant_hold():
            write_delegation_file(client_a, hold_path, "seed-tsm-deleg\n")
            wait_for_delegation_path(
                client_a, hold_path, "seed hold file", retries=path_wait_retries
            )
            wait_for_delegation_path(
                client_b, hold_path, "peer sees hold file", retries=path_wait_retries
            )
            log.info("Waiting %ss after seed for prior delegations to exit", exit_wait)
            time.sleep(exit_wait)

            hold_since, _ = get_node_time(peers)
            hits = capture_delegation_ganesha_log_phase(
                server,
                container_id,
                settle_s,
                lambda: (
                    hold_delegation_open(client_a, hold_path, "r+b", hold_duration),
                    time.sleep(ready_s),
                ),
            )
            validate_delegation_grant_capture("tsm_deleg_grant_hold", hits, "write")
            if _wait_counts(
                peers,
                nfs_name,
                hold_since,
                base_open + 1,
                base_lock,
                base_deleg + 1,
                "grant_hold",
            ):
                raise OperationFailedError(
                    "peer TSM summary did not show open+1 deleg+1 after WRITE hold"
                )

        if not _step(results, "1_grant_hold_open_deleg", step_grant_hold):
            return _log_summary(results)

        # ------------------------------------------------------------------
        # Step 2: Client B conflict while A holds → recall
        # Expect: recall in Ganesha; after settle peer deleg back toward base
        #         (A may still hold OPEN until step 3)
        # ------------------------------------------------------------------
        def step_conflict_recall():
            conflict_since, _ = get_node_time(peers)
            hits = capture_delegation_ganesha_log_phase(
                server,
                container_id,
                settle_s,
                lambda: write_delegation_file(
                    client_b, hold_path, "client-b-conflict\n", append=True
                ),
            )
            validate_delegation_recall_ganesha_capture(
                "tsm_deleg_peer_conflict", hits, True
            )
            # After recall/return of DELEG, open may still be +1 (A hold), deleg → base
            if _wait_counts(
                peers,
                nfs_name,
                conflict_since,
                base_open + 1,
                base_lock,
                base_deleg,
                "conflict_recall",
            ):
                raise OperationFailedError(
                    "peer TSM summary did not drop deleg to baseline after recall"
                )

        if not _step(results, "2_peer_conflict_recall", step_conflict_recall):
            return _log_summary(results)

        # ------------------------------------------------------------------
        # Step 3: Graceful CLOSE / DELEGRETURN → baseline
        # Expect: DELEGRETURN; peer open/deleg at baseline
        # ------------------------------------------------------------------
        def step_return_baseline():
            return_since, _ = get_node_time(peers)
            truncate_ganesha_container_log(server, container_id)
            start_ganesha_delegation_tailf_follow(server, container_id)
            try:
                release_delegation_hold_gracefully(client_a, term_wait_seconds=5)
                if not wait_for_delegreturn_in_ganesha_capture(
                    server, container_id, timeout_seconds=return_wait + 30
                ):
                    log.warning(
                        "DELEGRETURN not seen after release (may already returned "
                        "during recall); continuing with TSM baseline check"
                    )
            finally:
                stop_ganesha_delegation_tailf_follow(server, container_id)

            if _wait_counts(
                peers,
                nfs_name,
                return_since,
                base_open,
                base_lock,
                base_deleg,
                "return_baseline",
            ):
                raise OperationFailedError(
                    "peer TSM summary did not return to baseline after CLOSE/DELEGRETURN"
                )

        if not _step(results, "3_close_delegreturn_baseline", step_return_baseline):
            return _log_summary(results)

        # ------------------------------------------------------------------
        # Step 4: touch → WRITE_ATTRS grant; force return via peer write
        # Expect: type 5 grant; after peer write, counters at baseline
        # ------------------------------------------------------------------
        def step_touch():
            client_a.exec_command(
                sudo=True, cmd=f"rm -f {touch_path}", check_ec=False
            )
            touch_since, _ = get_node_time(peers)
            hits = capture_delegation_ganesha_log_phase(
                server,
                container_id,
                settle_s,
                lambda: client_a.exec_command(
                    sudo=True, cmd=f"touch {touch_path}", check_ec=True
                ),
            )
            validate_delegation_grant_capture("tsm_deleg_touch", hits, "write")
            # touch CLOSES open; ATTRS DELEG may remain → open=base, deleg=base+1
            snap = None
            deadline = time.time() + POLL_TIMEOUT
            while time.time() < deadline:
                snap = _peer_summary(peers, nfs_name, since=touch_since)
                if snap.get("seen") and snap["open"] == base_open:
                    break
                time.sleep(POLL_INTERVAL)
            if not snap or not snap.get("seen") or snap["open"] != base_open:
                raise OperationFailedError(
                    "after touch, peer open did not return to baseline (last=%s)" % snap
                )
            if snap["deleg"] not in (base_deleg, base_deleg + 1):
                raise OperationFailedError(
                    "after touch, unexpected peer deleg=%s (want %s or %s)"
                    % (snap["deleg"], base_deleg, base_deleg + 1)
                )
            log.info(
                "after touch: open=%s deleg=%s (ATTRS DELEG may outlive CLOSE)",
                snap["open"],
                snap["deleg"],
            )
            if snap["deleg"] == base_deleg + 1:
                force_since, _ = get_node_time(peers)
                write_delegation_file(
                    client_b, touch_path, "force-return\n", append=True
                )
                if _wait_counts(
                    peers,
                    nfs_name,
                    force_since,
                    base_open,
                    base_lock,
                    base_deleg,
                    "touch_force_return",
                ):
                    raise OperationFailedError(
                        "peer TSM deleg did not return to baseline after touch conflict"
                    )

        if not _step(results, "4_touch_grant", step_touch):
            return _log_summary(results)

        # ------------------------------------------------------------------
        # Step 5: export delegations=none → no DELEG grant / no deleg bump
        # ------------------------------------------------------------------
        def step_none_export():
            update_export_delegation(nfs_cmd_host, nfs_name, export, "none")
            NfsMultiActiveDelegation.assert_export_delegation(
                nfs_cmd_host, nfs_name, export, "none"
            )
            write_delegation_file(client_a, none_path, "none-seed\n")
            wait_for_delegation_path(
                client_a, none_path, "none seed", retries=path_wait_retries
            )
            time.sleep(exit_wait)

            none_since, _ = get_node_time(peers)
            hits = capture_delegation_ganesha_log_phase(
                server,
                container_id,
                settle_s,
                lambda: (
                    hold_delegation_open(client_a, none_path, "r+b", hold_duration),
                    time.sleep(ready_s),
                ),
            )
            types = parse_nfs4_open_delegation_types("\n".join(hits or []))
            if any(t in (4, 5) for t in types):
                raise OperationFailedError(
                    "delegations=none but saw read/write delegation types %r" % types
                )
            if _wait_counts(
                peers,
                nfs_name,
                none_since,
                base_open + 1,
                base_lock,
                base_deleg,
                "none_export_hold",
            ):
                raise OperationFailedError(
                    "peer TSM summary wrong on delegations=none hold "
                    "(expect open+1, deleg unchanged)"
                )
            release_delegation_hold_gracefully(client_a, term_wait_seconds=5)
            if _wait_counts(
                peers,
                nfs_name,
                none_since,
                base_open,
                base_lock,
                base_deleg,
                "none_export_release",
            ):
                raise OperationFailedError(
                    "peer TSM summary did not return to baseline after none-export release"
                )
            NfsMultiActiveDelegation.enable_rw_export(nfs_cmd_host, nfs_name, export)

        if not _step(results, "5_export_none_no_deleg", step_none_export):
            return _log_summary(results)

        results["workflow"] = "passed"
        rc = _log_summary(results)
    except Exception as exc:
        log.error("TSM delegation workflow FAILED: %s", exc)
        results.setdefault("error", "failed")
        rc = _log_summary(results)
    finally:
        for client in use_clients:
            kill_delegation_holds(client)
        try:
            if container_id:
                stop_ganesha_delegation_tailf_follow(server, container_id)
                truncate_ganesha_container_log(server, container_id)
        except Exception as err:
            log.warning("Ganesha log cleanup failed: %s", err)
        try:
            restore_delegation_ganesha_templates(
                nfs_cmd_host,
                delegation_template_backup,
                logging_template_backup,
                cephadm,
                installer,
                redeploy_wait,
                service_wait,
            )
        except Exception as err:
            log.warning("Ganesha template restore failed: %s", err)
        safe_cleanup(use_clients[0], mount, nfs_name, export, nodes)
        for client in use_clients[1:]:
            client.exec_command(
                sudo=True, cmd=f"umount -l {mount} 2>/dev/null", check_ec=False
            )

    return rc
