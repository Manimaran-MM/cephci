"""
NFS-Ganesha xcopy / COPY offload cases (shared community/cephadm setup).

Cases:
  1) intra_export_copy_offload_on  — XCOPY-01 (fs == fs)
  2) cross_export_copy_offload_on  — XCOPY-02 (fs1 != fs2)

Each case runs its workload, then a grouped validation sequence.

Community (--product community):
  - Skip cephadm NFS deploy / export create / cluster config debug
  - Patch host /etc/ganesha/ganesha.conf and restart nfs-ganesha
  - Intra-only: mount existing export (default Pseudo /cephfs)
  - With cross case: two CephFS subvolumes + two host EXPORT Pseudos
  - Validate against /var/log/ganesha/ganesha.log

Non-community (cephadm):
  - Intra-only: setup_nfs_cluster + ceph nfs cluster config set
  - With cross case: multi-export (export_num=2) + cluster config set
  - Validate against podman logs (same style as TSM)

Config:
  test_cases: list of case names (default: [intra_export_copy_offload_on])
"""

from nfs_operations import (
    cleanup_cluster,
    cleanup_custom_nfs_cluster_multi_export_client,
    setup_custom_nfs_cluster_multi_export_client,
    setup_nfs_cluster,
)

from cli.exceptions import ConfigError, OperationFailedError
from tests.nfs.lib.common_lib import get_node_time
from tests.nfs.lib.xcopy import (
    DEFAULT_PCAP_PATH,
    HOST_GANESHA_LOG,
    configure_host_ganesha_xcopy,
    copy_across_exports,
    copy_within_export,
    create_test_file,
    create_xcopy_subvolumes,
    ensure_copy_offload,
    ensure_host_cross_exports,
    ganesha_log_line_mark,
    is_community_product,
    mount_host_export,
    start_xcopy_pcap_capture,
    stop_xcopy_pcap_capture,
    verify_copy_offload_logs,
    verify_files_match,
    verify_files_shasum,
    verify_xcopy_pcap,
)
from tests.nfs.lib.xcopy.helpers import announce
from utility.log import Log

log = Log(__name__)

CROSS_CASE = "cross_export_copy_offload_on"


# ---------------------------------------------------------------------------
# Context / setup / cleanup
# ---------------------------------------------------------------------------


def _build_ctx(ceph_cluster, config, case_names):
    """Resolve nodes and common paths/params into a shared case context."""
    clients = ceph_cluster.get_nodes("client")
    nfs_nodes = ceph_cluster.get_nodes("nfs")
    installers = ceph_cluster.get_nodes("installer")

    log.info(
        "Cluster nodes: clients=%s nfs=%s installers=%s",
        [c.hostname for c in clients],
        [n.hostname for n in nfs_nodes],
        [i.hostname for i in installers],
    )

    port = config.get("port", "2049")
    version = str(config.get("nfs_version", "4.2"))
    no_clients = int(config.get("clients", 1))
    size_mb = int(config.get("file_size_mb", 64))
    chunk_size_mb = int(config.get("chunk_size_mb", 64))
    copy_mode = config.get("copy_mode", "any")
    community = is_community_product(config)
    need_cross = CROSS_CASE in case_names

    nfs_mount = config.get("nfs_mount", "/mnt/nfs")
    export_pseudo = config.get("export_pseudo", "/cephfs")
    export_pseudo_a = config.get("export_pseudo_a", "/cephfs_a")
    export_pseudo_b = config.get("export_pseudo_b", "/cephfs_b")
    ganesha_log_path = config.get("ganesha_log_path", HOST_GANESHA_LOG)
    pcap_path = config.get("pcap_path", DEFAULT_PCAP_PATH)
    pcap_validate = config.get("pcap_validate", True)
    pcap_offload_enabled = config.get("pcap_offload_enabled", True)

    if no_clients > len(clients):
        raise ConfigError("The test requires more clients than available")
    if chunk_size_mb < 1 or size_mb < 1:
        raise ConfigError("file_size_mb and chunk_size_mb must be >= 1")

    clients = clients[:no_clients]
    client = clients[0]

    if community:
        ganesha_node = (installers or nfs_nodes or [None])[0]
        if not ganesha_node:
            raise ConfigError("No installer/nfs node for host Ganesha")
        nfs_nodes_for_logs = [ganesha_node]
        log.info(
            "Community Ganesha host=%s (from %s)",
            ganesha_node.hostname,
            "installer" if installers else "nfs",
        )
    else:
        if not nfs_nodes:
            raise ConfigError("No NFS nodes found in the cluster")
        ganesha_node = nfs_nodes[0]
        nfs_nodes_for_logs = nfs_nodes
        log.info(
            "Cephadm NFS nodes for logs: %s (primary=%s)",
            [n.hostname for n in nfs_nodes_for_logs],
            ganesha_node.hostname,
        )

    nfs_name = config.get("nfs_name", "cephfs-nfs")
    nfs_export = config.get("nfs_export", "/export")
    export_num = 2 if need_cross else 1

    # Mount paths: dual setup uses *_a/*_b (community) or *_0/*_1 (cephadm).
    if need_cross:
        if community:
            nfs_mount_a = f"{nfs_mount}_a"
            nfs_mount_b = f"{nfs_mount}_b"
        else:
            nfs_mount_a = f"{nfs_mount}_0"
            nfs_mount_b = f"{nfs_mount}_1"
    else:
        nfs_mount_a = nfs_mount
        nfs_mount_b = nfs_mount

    return {
        "ceph_cluster": ceph_cluster,
        "config": config,
        "clients": clients,
        "client": client,
        "nfs_nodes": nfs_nodes,
        "nfs_nodes_for_logs": nfs_nodes_for_logs,
        "ganesha_node": ganesha_node,
        "community": community,
        "need_cross": need_cross,
        "port": port,
        "version": version,
        "size_mb": size_mb,
        "chunk_size_mb": chunk_size_mb,
        "copy_mode": copy_mode,
        "nfs_mount": nfs_mount,
        "nfs_mount_a": nfs_mount_a,
        "nfs_mount_b": nfs_mount_b,
        "export_pseudo": export_pseudo,
        "export_pseudo_a": export_pseudo_a,
        "export_pseudo_b": export_pseudo_b,
        "ganesha_log_path": ganesha_log_path,
        "pcap_path": pcap_path,
        "pcap_validate": pcap_validate,
        "pcap_offload_enabled": pcap_offload_enabled,
        "nfs_name": nfs_name,
        "nfs_export": nfs_export,
        "export_num": export_num,
        "fs_name": "cephfs",
        "fs": "cephfs",
        # Per-case paths / timing set in each case before validations.
        "src": None,
        "dst": None,
        "copy_elapsed_sec": None,
        "file_size_bytes": size_mb * 1024 * 1024,
        "chunk_size_bytes": chunk_size_mb * 1024 * 1024,
        "log_since": None,
        "log_from_line": 0,
        "server_ip": getattr(ganesha_node, "ip_address", None) or ganesha_node.hostname,
        "subvolumes": [],
    }


def _setup_cluster(ctx):
    """One-time deploy/mount/config before cases run."""
    community = ctx["community"]
    client = ctx["client"]
    ganesha_node = ctx["ganesha_node"]
    need_cross = ctx["need_cross"]

    announce(
        "SETUP xcopy COPY Offload "
        f"(product={'community' if community else 'cephadm'}, "
        f"cross={'yes' if need_cross else 'no'}, "
        f"size={ctx['size_mb']}MiB, chunk={ctx['chunk_size_mb']}MiB)"
    )
    log.info(
        "Client=%s Ganesha host=%s mounts=%s,%s nfsvers=%s",
        client.hostname,
        ganesha_node.hostname,
        ctx["nfs_mount_a"],
        ctx["nfs_mount_b"],
        ctx["version"],
    )

    if community:
        if need_cross:
            announce(
                "Community path: two CephFS subvolumes + two host EXPORTs; "
                "skip cephadm deploy"
            )
            subvols = create_xcopy_subvolumes(client, fs_name=ctx["fs_name"])
            ctx["subvolumes"] = subvols
            configure_host_ganesha_xcopy(
                ganesha_node,
                enabled=True,
                chunk_size_mb=ctx["chunk_size_mb"],
                restart=False,
            )
            ensure_host_cross_exports(
                ganesha_node,
                [
                    {
                        "export_id": 1,
                        "path": subvols[0]["path"],
                        "pseudo": ctx["export_pseudo_a"],
                    },
                    {
                        "export_id": 2,
                        "path": subvols[1]["path"],
                        "pseudo": ctx["export_pseudo_b"],
                    },
                ],
                restart=True,
            )
            mount_host_export(
                client,
                ganesha_node,
                nfs_mount=ctx["nfs_mount_a"],
                export_pseudo=ctx["export_pseudo_a"],
                version=ctx["version"],
                port=ctx["port"],
            )
            mount_host_export(
                client,
                ganesha_node,
                nfs_mount=ctx["nfs_mount_b"],
                export_pseudo=ctx["export_pseudo_b"],
                version=ctx["version"],
                port=ctx["port"],
            )
        else:
            announce(
                "Community path: skip cephadm deploy/export/debug; "
                "use host ganesha.conf + ganesha.log"
            )
            configure_host_ganesha_xcopy(
                ganesha_node,
                enabled=True,
                chunk_size_mb=ctx["chunk_size_mb"],
            )
            mount_host_export(
                client,
                ganesha_node,
                nfs_mount=ctx["nfs_mount"],
                export_pseudo=ctx["export_pseudo"],
                version=ctx["version"],
                port=ctx["port"],
            )
    else:
        if need_cross:
            announce(
                "Cephadm path: multi-export setup (Subvol-A + Subvol-B) "
                "+ cluster config set"
            )
            setup_custom_nfs_cluster_multi_export_client(
                ctx["clients"],
                ganesha_node.hostname,
                ctx["port"],
                ctx["version"],
                ctx["nfs_name"],
                ctx["fs_name"],
                ctx["fs"],
                ctx["nfs_mount"],
                ctx["nfs_export"],
                export_num=ctx["export_num"],
                ceph_cluster=ctx["ceph_cluster"],
            )
        else:
            announce("Cephadm path: setup_nfs_cluster + cluster config set")
            setup_nfs_cluster(
                ctx["clients"],
                ganesha_node.hostname,
                ctx["port"],
                ctx["version"],
                ctx["nfs_name"],
                ctx["nfs_mount"],
                ctx["fs_name"],
                ctx["nfs_export"],
                ctx["fs"],
                ceph_cluster=ctx["ceph_cluster"],
                single_export=True,
            )
        ensure_copy_offload(
            client,
            ctx["nfs_name"],
            enabled=True,
            chunk_size_mb=ctx["chunk_size_mb"],
        )


def _cleanup_cluster(ctx):
    """Tear down mounts/files (community) or NFS cluster (cephadm)."""
    if ctx["community"]:
        announce("Community cleanup: remove test files and unmount")
        client = ctx["client"]
        mounts = {ctx["nfs_mount_a"], ctx["nfs_mount_b"], ctx["nfs_mount"]}
        for mnt in mounts:
            client.exec_command(
                sudo=True,
                cmd=f"rm -f {mnt}/xcopy_*.bin",
                check_ec=False,
            )
            client.exec_command(
                sudo=True,
                cmd=(
                    f"if mountpoint -q {mnt}; then "
                    f"umount -l {mnt}; fi"
                ),
                check_ec=False,
            )
            out, _ = client.exec_command(
                sudo=True,
                cmd=(
                    f"if mountpoint -q {mnt}; then "
                    f"echo still-mounted; mount | grep -F '{mnt}'; "
                    f"else echo unmounted; fi"
                ),
                check_ec=False,
            )
            log.info("Mount %s after cleanup:\n%s", mnt, (out or "").strip())
    elif ctx["need_cross"]:
        announce("Cephadm cleanup: cleanup_custom_nfs_cluster_multi_export_client")
        cleanup_custom_nfs_cluster_multi_export_client(
            ctx["clients"],
            ctx["nfs_mount"],
            ctx["nfs_name"],
            ctx["nfs_export"],
            ctx["export_num"],
            nfs_nodes=ctx["nfs_nodes"],
        )
    else:
        announce("Cephadm cleanup: cleanup_cluster")
        cleanup_cluster(
            ctx["clients"],
            ctx["nfs_mount"],
            ctx["nfs_name"],
            ctx["nfs_export"],
            nfs_nodes=ctx["nfs_nodes"],
        )


# ---------------------------------------------------------------------------
# Grouped validations (run one after another)
# ---------------------------------------------------------------------------


def _mark_logs(ctx):
    """Mark log position immediately before the copy window."""
    if ctx["community"]:
        announce(f"Mark ganesha.log byte offset ({ctx['ganesha_log_path']})")
        ctx["log_from_line"] = ganesha_log_line_mark(
            ctx["ganesha_node"], log_path=ctx["ganesha_log_path"]
        )
        log.info("ganesha.log byte mark = %s", ctx["log_from_line"])
    else:
        ctx["log_since"], _ = get_node_time(ctx["nfs_nodes_for_logs"])
        log.info("podman log since marker: %s", ctx["log_since"])


def _validate_data_integrity(ctx):
    """cmp src vs dst."""
    if not verify_files_match(ctx["client"], ctx["src"], ctx["dst"]):
        raise OperationFailedError(
            f"Copy produced mismatched files ({ctx['src']} vs {ctx['dst']})"
        )
    return True


def _validate_shasum(ctx):
    """sha256sum src vs dst (after cmp)."""
    if not verify_files_shasum(ctx["client"], ctx["src"], ctx["dst"]):
        raise OperationFailedError(
            f"SHA256 mismatch after copy ({ctx['src']} vs {ctx['dst']})"
        )
    return True


def _validate_copy_elapsed(ctx):
    """Report wall-clock seconds captured for the cp operation."""
    elapsed = ctx.get("copy_elapsed_sec")
    announce(f"cp elapsed time: {elapsed}s")
    if elapsed is None:
        raise OperationFailedError("cp elapsed time was not captured")
    log.info(
        "PASS: cp took %.3fs for %s MiB (%s -> %s)",
        float(elapsed),
        ctx["size_mb"],
        ctx["src"],
        ctx["dst"],
    )
    return True


def _validate_pcap(ctx):
    """tcpdump / capinfos / tshark offload checks (skipped if disabled)."""
    if not ctx["pcap_validate"]:
        log.info("pcap_validate=false; skipping pcap validation")
        return True
    if not verify_xcopy_pcap(
        ctx["client"],
        ctx["pcap_path"],
        file_size_bytes=ctx["file_size_bytes"],
        offload_enabled=ctx["pcap_offload_enabled"],
    ):
        raise OperationFailedError(
            "xcopy pcap validation failed "
            f"(pcap={ctx['pcap_path']}, size={ctx['size_mb']}MiB, "
            f"Copy_Offload={'ON' if ctx['pcap_offload_enabled'] else 'OFF'})"
        )
    return True


def _validate_ganesha_logs(ctx):
    """Ganesha log milestones + chunk-size math."""
    if not verify_copy_offload_logs(
        ctx["nfs_nodes_for_logs"],
        ctx["nfs_name"],
        file_size_bytes=ctx["file_size_bytes"],
        chunk_size_bytes=ctx["chunk_size_bytes"],
        since=ctx["log_since"],
        mode=ctx["copy_mode"],
        community=ctx["community"],
        ganesha_log_path=ctx["ganesha_log_path"],
        log_from_line=ctx["log_from_line"],
    ):
        raise OperationFailedError(
            "xcopy log / chunk-size validation failed "
            f"(product={'community' if ctx['community'] else 'cephadm'}, "
            f"mode={ctx['copy_mode']}, size={ctx['size_mb']}MiB, "
            f"chunk={ctx['chunk_size_mb']}MiB)"
        )
    return True


def _run_validations(ctx, validations):
    """
    Run grouped validations sequentially.

    ``validations`` is a list of (name, callable) where callable(ctx) returns
    truthy on success or raises OperationFailedError.
    """
    announce(f"VALIDATIONS ({len(validations)} step(s))")
    for idx, (name, fn) in enumerate(validations, 1):
        announce(f"Validation {idx}/{len(validations)}: {name}")
        log.info("Running validation: %s", name)
        ok = fn(ctx)
        if not ok:
            raise OperationFailedError(f"Validation failed: {name}")
        log.info("PASS validation: %s", name)
    announce("VALIDATIONS complete")


def _default_validations():
    """Shared validation sequence for xcopy cases."""
    return [
        ("data_integrity_cmp", _validate_data_integrity),
        ("data_integrity_shasum", _validate_shasum),
        ("copy_elapsed", _validate_copy_elapsed),
        ("pcap_offload", _validate_pcap),
        ("ganesha_logs", _validate_ganesha_logs),
    ]


def _run_copy_with_pcap(ctx, copy_fn):
    """Create source, optionally capture pcap around copy_fn(client, src, dst)."""
    client = ctx["client"]
    src, dst = ctx["src"], ctx["dst"]
    _mark_logs(ctx)
    create_test_file(client, src, size_mb=ctx["size_mb"])

    tcpdump_pid = None
    if ctx["pcap_validate"]:
        tcpdump_pid = start_xcopy_pcap_capture(
            client,
            ctx["server_ip"],
            port=ctx["port"],
            pcap_path=ctx["pcap_path"],
        )
    try:
        ctx["copy_elapsed_sec"] = copy_fn(client, src, dst)
        log.info(
            "Recorded cp elapsed: %.3fs (%s -> %s)",
            float(ctx["copy_elapsed_sec"]),
            src,
            dst,
        )
    finally:
        if tcpdump_pid is not None:
            stop_xcopy_pcap_capture(client, ctx["pcap_path"], tcpdump_pid)


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


def case_intra_export_copy_offload_on(ctx):
    """
    XCOPY-01: Copy_Offload enabled — intra-export cp (fs == fs).

    Workload, then grouped validations:
      1) data integrity (cmp)
      2) data integrity (sha256sum)
      3) cp elapsed time
      4) pcap (COPY present, no READ/WRITE, low data)
      5) Ganesha logs (milestones + chunk math)
    """
    announce("================================================")
    announce("CASE: intra_export_copy_offload_on (XCOPY-01)")
    announce("================================================")
    ctx["src"] = f"{ctx['nfs_mount_a']}/xcopy_sync_src.bin"
    ctx["dst"] = f"{ctx['nfs_mount_a']}/xcopy_sync_dst.bin"

    _run_copy_with_pcap(ctx, copy_within_export)
    _run_validations(ctx, _default_validations())
    announce("PASS CASE: intra_export_copy_offload_on")


def case_cross_export_copy_offload_on(ctx):
    """
    XCOPY-02: Copy_Offload enabled — cross-export cp (fs1 != fs2).

    Mount Export-1 (Subvol-A) and Export-2 (Subvol-B); copy Export-1 -> Export-2.
    Same grouped validations as XCOPY-01.
    """
    announce("================================================")
    announce("CASE: cross_export_copy_offload_on (XCOPY-02)")
    announce("================================================")
    if not ctx["need_cross"]:
        raise ConfigError(
            "cross_export_copy_offload_on selected but dual-export setup was skipped"
        )
    ctx["src"] = f"{ctx['nfs_mount_a']}/xcopy_cross_src.bin"
    ctx["dst"] = f"{ctx['nfs_mount_b']}/xcopy_cross_dst.bin"

    _run_copy_with_pcap(ctx, copy_across_exports)
    _run_validations(ctx, _default_validations())
    announce("PASS CASE: cross_export_copy_offload_on")


CASES = {
    "intra_export_copy_offload_on": case_intra_export_copy_offload_on,
    "cross_export_copy_offload_on": case_cross_export_copy_offload_on,
}


def run(ceph_cluster, **kw):
    """
    Run one or more xcopy cases from this module.

    ``config.test_cases`` selects which cases to run (list). Default is the
    intra-export Copy_Offload=ON case only.
    """
    config = kw.get("config") or {}
    case_names = config.get("test_cases") or ["intra_export_copy_offload_on"]
    if isinstance(case_names, str):
        case_names = [case_names]

    unknown = [n for n in case_names if n not in CASES]
    if unknown:
        raise ConfigError(
            f"Unknown test_cases {unknown}; valid: {sorted(CASES)}"
        )

    ctx = _build_ctx(ceph_cluster, config, case_names)
    log.info("Running test_cases=%s need_cross=%s", case_names, ctx["need_cross"])

    try:
        _setup_cluster(ctx)
        for name in case_names:
            announce(f"RUN CASE: {name}")
            CASES[name](ctx)
        announce(
            "PASS xcopy COPY offload module "
            f"(cases={case_names}, "
            f"product={'community' if ctx['community'] else 'cephadm'})"
        )
        log.info("Test result: PASS (return 0)")
        return 0
    except Exception as exc:
        log.error("xcopy COPY offload module failed: %s", exc)
        log.info("Test result: FAIL (return 1)")
        return 1
    finally:
        _cleanup_cluster(ctx)
