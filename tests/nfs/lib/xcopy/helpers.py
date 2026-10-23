"""Helpers for NFS xcopy / COPY offload validation."""

import re
import time

from cli.utilities.filesys import Mount
from tests.nfs.lib.common_lib import (
    enable_nfs_debug_logs,
    get_nfs_container_id,
)
from tests.nfs.security.security_utils import ensure_package_installed
from utility.log import Log

log = Log(__name__)

HOST_GANESHA_CONF = "/etc/ganesha/ganesha.conf"
HOST_GANESHA_LOG = "/var/log/ganesha/ganesha.log"
DEFAULT_PCAP_PATH = "/tmp/nfs-xcopy-cp.pcap"
# Per-hostname cache so ensure_xcopy_pcap_tools is not re-run.
_PCAP_TOOLS_READY = set()
# NFSv4 opcodes (RFC 7530 / 7862) as reported by tshark -e nfs.opcode
NFS_OPCODE_READ = "25"
NFS_OPCODE_WRITE = "38"
NFS_OPCODE_COPY = "60"  # OP_COPY
# Packages tried (in order) when a capture/analysis binary is missing.
PCAP_BINARIES = {
    "tcpdump": ("tcpdump",),
    "tshark": ("wireshark-cli", "wireshark"),
    "capinfos": ("wireshark-cli", "wireshark"),
}
# Capinfos / tshark expectations (Copy_Offload true vs false).
# ON:  packets = tens; data = KB–low MB; opcode 60 yes; 25/38 == 0
# OFF: packets = tens of thousands; data ≈ 2× file; 25/38 flood yes
PCAP_ON_MAX_PACKETS = 200
PCAP_ON_MAX_DATA_BYTES = 16 * 1024 * 1024  # 16 MiB ("low MB")
PCAP_ON_MAX_RW_OPS = 0  # READ(25)/WRITE(38) must be absent for offload
PCAP_OFF_MIN_PACKETS = 10000
PCAP_OFF_DATA_RATIO_MIN = 1.5
PCAP_OFF_DATA_RATIO_MAX = 2.5
PCAP_OFF_MIN_RW_OPS = 1000
# Wireshark 4.x prints "10 kB" / "11 kB"; older builds use "N bytes".
RE_CAPINFOS_DATA_SIZE = re.compile(
    r"Data size:\s*([\d,.]+)\s*(bytes?|kB|KiB|KB|MB|MiB|GB|GiB)?",
    re.I,
)
RE_CAPINFOS_FILE_SIZE = re.compile(
    r"File size:\s*([\d,.]+)\s*(bytes?|kB|KiB|KB|MB|MiB|GB|GiB)?",
    re.I,
)
RE_CAPINFOS_PACKETS = re.compile(r"Number of packets:\s*([\d,]+)", re.I)
RE_OPCODE_HIST = re.compile(r"^\s*(\d+)\s+(\S+)\s*$")
_CAPINFOS_UNITS = {
    None: 1,
    "": 1,
    "byte": 1,
    "bytes": 1,
    "kb": 1000,
    "kib": 1024,
    "mb": 1000**2,
    "mib": 1024**2,
    "gb": 1000**3,
    "gib": 1024**3,
}

RE_WORKER_START = re.compile(
    r"COPY (SYNC|ASYNC) worker START:\s*total=(\d+)\s+bytes\s+"
    r"src_off=(\d+)\s+dst_off=(\d+)\s+chunk_size=(\d+)",
    re.I,
)
RE_MDCACHE_OK = re.compile(r"COPY mdcache:\s*done OK copied=(\d+)", re.I)
RE_CB_OFFLOAD = re.compile(r"CB_OFFLOAD:\s*sending OK bytes=(\d+)\s+seqid=", re.I)
RE_OFFLOAD_STATE = re.compile(r"create_copy_offload_state", re.I)
RE_SUBMIT_JOB = re.compile(r"copy_submit_job", re.I)

# Remote grep ERE fragments (OR'd into one cumulative grep).
# Keep in sync with the RE_* validators above so evidence is easy to spot.
XCOPY_GREP_PATTERNS = (
    r"COPY (SYNC|ASYNC) worker START",
    r"COPY (SYNC|ASYNC) chunk #",
    r"COPY mdcache:.*done OK",
    r"CB_OFFLOAD:.*sending OK",
    r"create_copy_offload_state",
    r"copy_submit_job",
)


def announce(step):
    """Banner so each xcopy step is obvious in cephci logs."""
    log.info("\n========== [xcopy] %s ==========\n", step)


def is_community_product(config):
    """Return True when CephCI product is community (host NFS-Ganesha)."""
    product = str((config or {}).get("product", "")).lower()
    community = product == "community"
    log.info("product=%r -> community=%s", product or "<unset>", community)
    return community


def ensure_copy_offload(
    client,
    nfs_name,
    enabled=True,
    chunk_size_mb=64,
    short_copy=False,
    conf_file="nfs_xcopy.conf",
):
    """Cephadm path: set Copy_Offload via ``ceph nfs cluster config set``."""
    announce(f"Cephadm: set Copy_Offload on nfs.{nfs_name}")
    flag = "true" if enabled else "false"
    short_flag = "true" if short_copy else "false"
    chunk_bytes = int(chunk_size_mb) * 1024 * 1024
    log.info(
        "Building conf %s: Copy_Offload=%s Short_Copy=%s Chunk_Size=%s (%s MiB) "
        "for nfs.%s",
        conf_file,
        flag,
        short_flag,
        chunk_bytes,
        chunk_size_mb,
        nfs_name,
    )
    body = (
        "NFSv4 {\n"
        f"\tCopy_Offload = {flag};\n"
        f"\tShort_Copy = {short_flag};\n"
        f"\tCopy_Offload_Chunk_Size = {chunk_bytes};\n"
        "}\n"
    )
    conf = client.remote_file(sudo=True, file_name=conf_file, file_mode="w")
    conf.write(body)
    conf.flush()
    out, _ = client.exec_command(sudo=True, cmd=f"cat {conf_file}")
    log.info("xcopy conf %s:\n%s", conf_file, (out or "").strip())
    client.exec_command(
        sudo=True, cmd=f"ceph nfs cluster config set {nfs_name} -i {conf_file}"
    )
    log.info(
        "Applied Copy_Offload=%s Short_Copy=%s Copy_Offload_Chunk_Size=%s (%s MiB) "
        "on nfs.%s",
        flag,
        short_flag,
        chunk_bytes,
        chunk_size_mb,
        nfs_name,
    )
    log.info("Enabling NFS4 FULL_DEBUG on nfs.%s", nfs_name)
    enable_nfs_debug_logs(client, nfs_name, "NFS4")
    log.info("Copy_Offload config + debug logs done for nfs.%s", nfs_name)


def _set_or_insert_nfsv4_key(text, key, value):
    """Set ``key = value;`` inside NFSv4 {}, inserting the block/key if needed."""
    assignment = f"  {key} = {value};"

    def repl_key(match):
        body = match.group(1)
        if re.search(rf"^\s*#?\s*{key}\s*=", body, flags=re.M | re.I):
            log.info("Updating existing NFSv4 key %s = %s", key, value)
            body = re.sub(
                rf"^\s*#?\s*{key}\s*=\s*[^;]+;",
                assignment,
                body,
                count=1,
                flags=re.M | re.I,
            )
        else:
            log.info("Inserting NFSv4 key %s = %s into existing block", key, value)
            body = body.rstrip() + "\n" + assignment + "\n"
        return "NFSv4 {" + body + "}"

    if re.search(r"NFSv4\s*\{", text, flags=re.I):
        return re.sub(
            r"NFSv4\s*\{(.*?)\}",
            repl_key,
            text,
            count=1,
            flags=re.S | re.I,
        )
    log.info("No NFSv4 block found; appending new block with %s = %s", key, value)
    return text.rstrip() + f"\n\nNFSv4 {{\n{assignment}\n}}\n"


def configure_host_ganesha_xcopy(
    node,
    enabled=True,
    chunk_size_mb=64,
    short_copy=False,
    conf_path=HOST_GANESHA_CONF,
    restart=True,
):
    """
    Community path: update host ``/etc/ganesha/ganesha.conf`` in place and
    restart nfs-ganesha. Preserves EXPORT / CEPH / other blocks.
    """
    announce(f"Configure host ganesha.conf on {node.hostname}")
    flag = "true" if enabled else "false"
    short_flag = "true" if short_copy else "false"
    chunk_bytes = int(chunk_size_mb) * 1024 * 1024
    log.info(
        "Target conf=%s enabled=%s short_copy=%s chunk_size_mb=%s restart=%s "
        "host=%s",
        conf_path,
        flag,
        short_flag,
        chunk_size_mb,
        restart,
        node.hostname,
    )

    out, _ = node.exec_command(sudo=True, cmd=f"cat {conf_path}")
    text = out or ""
    log.info("Read %s: %s bytes", conf_path, len(text))
    if not text.strip():
        raise RuntimeError(f"Empty or missing ganesha conf: {conf_path}")

    node.exec_command(sudo=True, cmd=f"cp -a {conf_path} {conf_path}.bak.xcopy")
    log.info("Backup written: %s.bak.xcopy", conf_path)

    if re.search(r"Default_Log_Level\s*=", text, flags=re.I):
        text = re.sub(
            r"Default_Log_Level\s*=\s*[^;]+;",
            "Default_Log_Level = FULL_DEBUG;",
            text,
            count=1,
            flags=re.I,
        )
        log.info("Set Default_Log_Level = FULL_DEBUG")
    else:
        log.info("Default_Log_Level not present; leaving LOG block as-is")

    if re.search(r"COMPONENTS\s*\{", text, flags=re.I):
        text = re.sub(
            r"(COMPONENTS\s*\{)(.*?)(\})",
            r"\1\n  ALL = FULL_DEBUG;\n\3",
            text,
            count=1,
            flags=re.S | re.I,
        )
        log.info("Set COMPONENTS { ALL = FULL_DEBUG; }")
    else:
        log.info("COMPONENTS block not present; leaving LOG block as-is")

    text = _set_or_insert_nfsv4_key(text, "Copy_Offload", flag)
    text = _set_or_insert_nfsv4_key(text, "Short_Copy", short_flag)
    text = _set_or_insert_nfsv4_key(text, "Copy_Offload_Chunk_Size", str(chunk_bytes))

    tmp = "/tmp/ganesha_xcopy.conf"
    log.info("Writing patched conf to %s then installing to %s", tmp, conf_path)
    remote = node.remote_file(sudo=True, file_name=tmp, file_mode="w")
    remote.write(text)
    remote.flush()
    node.exec_command(sudo=True, cmd=f"cp -f {tmp} {conf_path}")
    log.info(
        "Wrote %s: Copy_Offload=%s Short_Copy=%s Copy_Offload_Chunk_Size=%s (%s MiB)",
        conf_path,
        flag,
        short_flag,
        chunk_bytes,
        chunk_size_mb,
    )

    out, _ = node.exec_command(
        sudo=True,
        cmd=f"awk '/NFSv4[[:space:]]*{{/,/^}}/' {conf_path}",
    )
    log.info("Active NFSv4 block:\n%s", (out or "").strip())

    out, _ = node.exec_command(sudo=True, cmd=f"cat {conf_path}")
    log.info("Final ganesha.conf (%s):\n%s", conf_path, (out or "").strip())

    if restart:
        announce(f"Restart nfs-ganesha on {node.hostname}")
        log.info("systemctl restart nfs-ganesha (timeout=120s)")
        node.exec_command(
            sudo=True, cmd="systemctl restart nfs-ganesha", timeout=120
        )
        out, _ = node.exec_command(sudo=True, cmd="systemctl is-active nfs-ganesha")
        log.info("nfs-ganesha is-active: %s", (out or "").strip())
    else:
        log.info("Skipping nfs-ganesha restart (restart=False)")


def mount_host_export(
    client,
    server,
    nfs_mount="/mnt/nfs",
    export_pseudo="/cephfs",
    version="4.2",
    port="2049",
):
    """Mount an already-configured host Ganesha export (community)."""
    server_ip = getattr(server, "ip_address", None) or server
    announce(
        f"Mount host export {server_ip}:{export_pseudo} -> {nfs_mount} "
        f"(vers={version}) on {client.hostname}"
    )
    log.info(
        "mount params: client=%s server=%s pseudo=%s mount=%s vers=%s port=%s",
        client.hostname,
        server_ip,
        export_pseudo,
        nfs_mount,
        version,
        port,
    )
    client.exec_command(sudo=True, cmd=f"mkdir -p {nfs_mount}")
    log.info("Ensured mount dir %s", nfs_mount)
    client.exec_command(
        sudo=True,
        cmd=f"if mountpoint -q {nfs_mount}; then umount -l {nfs_mount}; fi",
    )
    log.info("Cleared prior mount at %s if present", nfs_mount)
    Mount(client).nfs(nfs_mount, version, port, server_ip, export_pseudo)
    log.info("Mount() completed for %s", nfs_mount)
    out, _ = client.exec_command(
        sudo=True, cmd=f"mount | grep -F '{nfs_mount}'"
    )
    log.info("Mount table entry:\n%s", (out or "").strip())


def create_test_file(client, path, size_mb=64):
    """Create a test file of size_mb MiB under path (parent dirs must exist)."""
    announce(f"Create source file {path} ({size_mb} MiB) on {client.hostname}")
    # /dev/zero is far faster than urandom; content uniqueness is not required.
    client.exec_command(sudo=True, cmd=f"mkdir -p $(dirname {path})")
    client.exec_command(
        sudo=True,
        cmd=f"dd if=/dev/zero of={path} bs=1M count={int(size_mb)} status=none",
        timeout=600,
    )
    out, _ = client.exec_command(sudo=True, cmd=f"ls -lh {path}")
    log.info("Source file created: %s", (out or "").strip())


def _timed_cp(client, src, dst):
    """
    Run ``cp src dst`` and return wall-clock seconds (remote ``date``).

    ``rm -f dst`` is done first and not included in the elapsed time.
    """
    client.exec_command(sudo=True, cmd=f"rm -f {dst}")
    # Measure on the client host so SSH RTT is not counted as copy time.
    out, _ = client.exec_command(
        sudo=True,
        cmd=(
            f"start=$(date +%s.%N); cp {src} {dst} && end=$(date +%s.%N) && "
            f"awk -v s=\"$start\" -v e=\"$end\" 'BEGIN {{ printf \"%.3f\\n\", e - s }}'"
        ),
        timeout=600,
    )
    elapsed = float((out or "0").strip().splitlines()[-1])
    log.info("cp elapsed: %.3fs (%s -> %s)", elapsed, src, dst)
    out, _ = client.exec_command(sudo=True, cmd=f"ls -lh {src} {dst}")
    log.info("After copy:\n%s", (out or "").strip())
    return elapsed


def copy_within_export(client, src, dst):
    """Copy src -> dst on the same NFS mount (intra-export, fs == fs).

    Returns elapsed seconds for the ``cp`` itself.
    """
    announce(f"Intra-export cp {src} -> {dst} on {client.hostname}")
    return _timed_cp(client, src, dst)


def copy_across_exports(client, src, dst):
    """Copy src -> dst across two NFS mounts (cross-export, fs1 != fs2).

    Returns elapsed seconds for the ``cp`` itself.
    """
    announce(f"Cross-export cp {src} -> {dst} on {client.hostname}")
    return _timed_cp(client, src, dst)


def create_xcopy_subvolumes(
    client,
    fs_name="cephfs",
    group="xcopygroup",
    names=("xcopy_sv_a", "xcopy_sv_b"),
):
    """
    Create CephFS subvolumes for cross-export testing.

    Returns list of dicts: name, group, path, fs_name.
    """
    announce(f"Create CephFS subvolumes {list(names)} in group {group}")
    client.exec_command(
        sudo=True,
        cmd=f"ceph fs subvolumegroup create {fs_name} {group}",
        check_ec=False,
    )
    results = []
    for name in names:
        client.exec_command(
            sudo=True,
            cmd=(
                f"ceph fs subvolume create {fs_name} {name} "
                f"--group_name {group} --namespace-isolated"
            ),
            check_ec=False,
        )
        out, _ = client.exec_command(
            sudo=True,
            cmd=f"ceph fs subvolume getpath {fs_name} {name} --group_name {group}",
        )
        path = (out or "").strip()
        if not path:
            raise RuntimeError(
                f"Empty subvolume path for {name} (fs={fs_name} group={group})"
            )
        log.info("Subvolume %s path=%s", name, path)
        results.append(
            {"name": name, "group": group, "path": path, "fs_name": fs_name}
        )
    return results


def _host_fsal_user_id(conf_text, default="admin"):
    """Return FSAL User_Id from the first EXPORT block, if present."""
    m = re.search(
        r"EXPORT\s*\{.*?FSAL\s*\{.*?User_Id\s*=\s*\"?([^\";\s]+)\"?\s*;",
        conf_text or "",
        flags=re.S | re.I,
    )
    if m:
        return m.group(1)
    return default


def _export_block(export_id, path, pseudo, user_id="admin"):
    """Return a host-Ganesha EXPORT block for a CephFS path."""
    return (
        "EXPORT {\n"
        f"  Export_Id = {int(export_id)};\n"
        f'  Path = "{path}";\n'
        f'  Pseudo = "{pseudo}";\n'
        "  Access_Type = RW;\n"
        "  Squash = None;\n"
        "  Attr_Expiration_Time = 0;\n"
        "  Protocols = 3,4;\n"
        "  Transports = TCP;\n"
        "  FSAL {\n"
        "    Name = CEPH;\n"
        f'    User_Id = "{user_id}";\n'
        "  }\n"
        "}\n"
    )


def _strip_export_blocks(conf_text):
    """Remove EXPORT { ... } blocks, respecting nested braces (e.g. FSAL)."""
    text = conf_text or ""
    out = []
    i = 0
    while i < len(text):
        m = re.search(r"(?i)\bEXPORT\s*\{", text[i:])
        if not m:
            out.append(text[i:])
            break
        start = i + m.start()
        out.append(text[i:start])
        brace = i + m.end() - 1  # '{'
        depth = 0
        j = brace
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            j += 1
        i = j
    return "".join(out)


def ensure_host_exports(
    node,
    exports,
    conf_path=HOST_GANESHA_CONF,
    restart=True,
):
    """
    Community: replace EXPORT blocks with the given Pseudo/Path list.

    ``exports`` is a list of dicts with keys: export_id, path, pseudo.
    Preserves LOG / NFS_CORE_PARAM / NFSv4 / CEPH blocks.
    """
    announce(f"Ensure {len(exports)} host EXPORT block(s) on {node.hostname}")
    if not exports:
        raise RuntimeError("ensure_host_exports requires at least one EXPORT entry")

    out, _ = node.exec_command(sudo=True, cmd=f"cat {conf_path}")
    text = out or ""
    if not text.strip():
        raise RuntimeError(f"Empty or missing ganesha conf: {conf_path}")

    user_id = _host_fsal_user_id(text)
    log.info("Using FSAL User_Id=%s for new EXPORT blocks", user_id)

    stripped = _strip_export_blocks(text)
    stripped = re.sub(r"\n{3,}", "\n\n", stripped).rstrip() + "\n\n"

    blocks = []
    for exp in exports:
        blocks.append(
            _export_block(
                exp["export_id"],
                exp["path"],
                exp["pseudo"],
                user_id=user_id,
            )
        )
        log.info(
            "EXPORT Export_Id=%s Path=%s Pseudo=%s",
            exp["export_id"],
            exp["path"],
            exp["pseudo"],
        )
    new_text = stripped + "\n".join(blocks)

    tmp = "/tmp/ganesha_xcopy_cross.conf"
    remote = node.remote_file(sudo=True, file_name=tmp, file_mode="w")
    remote.write(new_text)
    remote.flush()
    node.exec_command(sudo=True, cmd=f"cp -f {tmp} {conf_path}")

    out, _ = node.exec_command(sudo=True, cmd=f"cat {conf_path}")
    log.info("Final ganesha.conf (%s):\n%s", conf_path, (out or "").strip())

    if restart:
        announce(f"Restart nfs-ganesha on {node.hostname}")
        node.exec_command(
            sudo=True, cmd="systemctl restart nfs-ganesha", timeout=120
        )
        out, _ = node.exec_command(sudo=True, cmd="systemctl is-active nfs-ganesha")
        log.info("nfs-ganesha is-active: %s", (out or "").strip())


def ensure_host_cross_exports(
    node,
    exports,
    conf_path=HOST_GANESHA_CONF,
    restart=True,
):
    """Community cross-export: require >=2 EXPORT blocks, then rewrite conf."""
    if len(exports) < 2:
        raise RuntimeError("Cross-export setup needs at least two EXPORT entries")
    return ensure_host_exports(
        node, exports, conf_path=conf_path, restart=restart
    )


def ensure_host_intra_export(
    node,
    path="/",
    pseudo="/cephfs",
    export_id=1,
    conf_path=HOST_GANESHA_CONF,
    restart=True,
):
    """
    Community intra-export: force a single EXPORT (default Pseudo /cephfs).

    Clears leftover dual-export Pseudos (e.g. /cephfs_a, /cephfs_b) from a
    prior cross-export run so mount of /cephfs succeeds.
    """
    announce(
        f"Ensure single host EXPORT Pseudo={pseudo} Path={path} on {node.hostname}"
    )
    return ensure_host_exports(
        node,
        [{"export_id": export_id, "path": path, "pseudo": pseudo}],
        conf_path=conf_path,
        restart=restart,
    )


def verify_files_match(client, src, dst):
    """Return True if src and dst have identical content (cmp)."""
    announce(f"Verify data integrity: cmp {src} {dst}")
    client.exec_command(sudo=True, cmd=f"cmp -s {src} {dst}", check_ec=False)
    if client.exit_status != 0:
        log.error(
            "File mismatch: %s vs %s (cmp rc=%s)",
            src,
            dst,
            client.exit_status,
        )
        out, _ = client.exec_command(sudo=True, cmd=f"ls -lh {src} {dst}")
        log.info("ls after cmp fail:\n%s", (out or "").strip())
        return False
    log.info("PASS: files match (%s == %s)", src, dst)
    return True


def verify_files_shasum(client, src, dst):
    """Return True if sha256 digests of src and dst match."""
    announce(f"Verify data integrity: sha256sum {src} {dst}")
    out, _ = client.exec_command(
        sudo=True, cmd=f"sha256sum {src} {dst}", timeout=600
    )
    text = (out or "").strip()
    log.info("sha256sum:\n%s", text if text else "<empty>")
    hashes = []
    for line in text.splitlines():
        parts = line.split()
        if parts:
            hashes.append(parts[0].lower())
    if len(hashes) < 2:
        log.error("Could not parse two sha256 digests from sha256sum output")
        return False
    if hashes[0] != hashes[1]:
        log.error(
            "SHA mismatch: %s (%s) vs %s (%s)",
            hashes[0],
            src,
            hashes[1],
            dst,
        )
        return False
    log.info("PASS: sha256 match (%s)", hashes[0])
    return True


def ensure_xcopy_pcap_tools(node):
    """
    Ensure ``tcpdump``, ``tshark``, and ``capinfos`` exist on ``node``.

    Uses ``ensure_package_installed`` when a binary is missing.
    Cached per hostname for the process lifetime.
    """
    host = getattr(node, "hostname", str(node))
    if host in _PCAP_TOOLS_READY:
        log.info("pcap tools already verified on %s", host)
        return

    announce(f"Ensure pcap tools on {host}")
    for binary, packages in PCAP_BINARIES.items():
        out, _ = node.exec_command(
            sudo=True, cmd=f"command -v {binary}", check_ec=False
        )
        path = (out or "").strip()
        if path:
            log.info("%s already present: %s", binary, path)
            continue
        log.info("%s missing on %s; trying packages %s", binary, host, packages)
        installed = False
        for pkg in packages:
            log.info("Installing package %s for %s", pkg, binary)
            ensure_package_installed(node, pkg)
            out, _ = node.exec_command(
                sudo=True, cmd=f"command -v {binary}", check_ec=False
            )
            path = (out or "").strip()
            if path:
                log.info("%s available after installing %s: %s", binary, pkg, path)
                installed = True
                break
        if not installed:
            raise RuntimeError(
                f"{binary} not found on {host} after trying {packages}"
            )
    _PCAP_TOOLS_READY.add(host)
    log.info("pcap tools ready on %s", host)


def _tcpdump_log_path(pcap_path):
    """Return side-car log path for a pcap capture."""
    return f"/tmp/tcpdump_{pcap_path.rsplit('/', 1)[-1]}.log"


def _tcpdump_pid_path(pcap_path):
    """Return pidfile path for a pcap capture."""
    return f"{pcap_path}.pid"


def start_xcopy_pcap_capture(client, server_host, port="2049", pcap_path=DEFAULT_PCAP_PATH):
    """
    Start full-snaplen tcpdump on the client.

    Equivalent: ``tcpdump -i any -s 0 -w <pcap> host <server> and tcp port <port>``.
    Uses a pidfile (not ``pkill -f``) to track the process. Returns pid.
    """
    announce(
        f"Start tcpdump capture on {client.hostname}: "
        f"host {server_host} port {port} -> {pcap_path}"
    )
    ensure_xcopy_pcap_tools(client)

    log_path = _tcpdump_log_path(pcap_path)
    pid_path = _tcpdump_pid_path(pcap_path)
    bpf = f"host {server_host} and tcp port {port}"

    # Stop any prior capture tracked by pidfile (do not use pkill -f).
    out, _ = client.exec_command(
        sudo=True, cmd=f"cat {pid_path}", check_ec=False
    )
    old_pid = (out or "").strip()
    if old_pid.isdigit():
        client.exec_command(
            sudo=True, cmd=f"kill {old_pid}", check_ec=False
        )
    client.exec_command(sudo=True, cmd=f"rm -f {pcap_path}")
    client.exec_command(sudo=True, cmd=f"rm -f {log_path}")
    client.exec_command(sudo=True, cmd=f"rm -f {pid_path}")

    # Background start must keep & and pidfile write in the same shell.
    client.exec_command(
        sudo=True,
        cmd=(
            f"nohup tcpdump -i any -s 0 -U -w {pcap_path} '{bpf}' "
            f">{log_path} 2>&1 </dev/null & echo $! > {pid_path}"
        ),
    )
    time.sleep(1)

    out, _ = client.exec_command(sudo=True, cmd=f"cat {pid_path}")
    pid = (out or "").strip()
    out, _ = client.exec_command(
        sudo=True, cmd=f"ps -p {pid} -o comm=", check_ec=False
    )
    if not pid.isdigit() or "tcpdump" not in str(out or ""):
        out, _ = client.exec_command(sudo=True, cmd=f"cat {log_path}", check_ec=False)
        log.info("tcpdump log:\n%s", (out or "").strip() or "<empty>")
        raise RuntimeError(
            f"tcpdump not running after start for {pcap_path} (pid={pid!r})"
        )
    out, _ = client.exec_command(
        sudo=True, cmd=f"ps -p {pid} -o pid=,comm=,args="
    )
    log.info("tcpdump running:\n%s", (out or "").strip())
    log.info("tcpdump pid=%s pcap=%s bpf=%r", pid, pcap_path, bpf)
    return pid


def stop_xcopy_pcap_capture(client, pcap_path, pid):
    """Stop tcpdump capture and confirm the pcap is flushed."""
    announce(f"Stop tcpdump capture pid={pid} pcap={pcap_path}")
    log_path = _tcpdump_log_path(pcap_path)
    pid_path = _tcpdump_pid_path(pcap_path)

    live = pid
    if not live:
        out, _ = client.exec_command(
            sudo=True, cmd=f"cat {pid_path}", check_ec=False
        )
        live = (out or "").strip()

    if live and str(live).isdigit():
        log.info("Stopping tcpdump pid=%s", live)
        client.exec_command(sudo=True, cmd=f"kill -TERM {live}", check_ec=False)
        for i in range(5):
            time.sleep(0.5)
            out, _ = client.exec_command(
                sudo=True, cmd=f"ps -p {live} -o comm=", check_ec=False
            )
            if not out or "tcpdump" not in str(out):
                log.info("tcpdump stopped after %.1fs", (i + 1) * 0.5)
                break
        else:
            client.exec_command(sudo=True, cmd=f"kill -KILL {live}", check_ec=False)
    else:
        log.info("No live tcpdump pid for %s", pcap_path)

    client.exec_command(sudo=True, cmd=f"rm -f {pid_path}", check_ec=False)
    out, _ = client.exec_command(sudo=True, cmd=f"ls -lh {pcap_path}")
    log.info("pcap after stop:\n%s", (out or "").strip())
    out, _ = client.exec_command(sudo=True, cmd=f"cat {log_path}", check_ec=False)
    log.info("tcpdump log:\n%s", (out or "").strip() or "<empty>")


def _capinfos_size_to_bytes(value, unit):
    """Convert capinfos size + unit (e.g. 10, 'kB') to integer bytes."""
    scale = _CAPINFOS_UNITS.get((unit or "").lower())
    if scale is None:
        return None
    return int(float(str(value).replace(",", "")) * scale)


def _parse_capinfos(text):
    """Return dict with data_size, file_size, packets from capinfos output."""
    def _size(regex):
        m = regex.search(text or "")
        if not m:
            return None
        return _capinfos_size_to_bytes(m.group(1), m.group(2))

    def _packets():
        m = RE_CAPINFOS_PACKETS.search(text or "")
        if not m:
            return None
        return int(m.group(1).replace(",", ""))

    return {
        "data_size": _size(RE_CAPINFOS_DATA_SIZE),
        "file_size": _size(RE_CAPINFOS_FILE_SIZE),
        "packets": _packets(),
    }


def _parse_opcode_histogram(text):
    """Return {opcode_label: count} from ``uniq -c | sort -nr`` output."""
    counts = {}
    for line in (text or "").splitlines():
        m = RE_OPCODE_HIST.match(line.strip())
        if not m:
            continue
        counts[m.group(2)] = int(m.group(1))
    return counts


def _opcode_count(opcodes, *labels):
    """Sum counts for numeric and/or named opcode labels (case-insensitive names)."""
    want = {str(x).upper() for x in labels}
    total = 0
    for key, count in (opcodes or {}).items():
        if str(key).upper() in want:
            total += int(count)
    return total


def verify_xcopy_pcap(
    client,
    pcap_path,
    file_size_bytes,
    offload_enabled=True,
    on_max_packets=PCAP_ON_MAX_PACKETS,
    on_max_data_bytes=PCAP_ON_MAX_DATA_BYTES,
    on_max_rw_ops=PCAP_ON_MAX_RW_OPS,
    off_min_packets=PCAP_OFF_MIN_PACKETS,
    off_data_ratio_min=PCAP_OFF_DATA_RATIO_MIN,
    off_data_ratio_max=PCAP_OFF_DATA_RATIO_MAX,
    off_min_rw_ops=PCAP_OFF_MIN_RW_OPS,
):
    """
    Validate Copy_Offload ON vs OFF from a client-side pcap.

    capinfos:
      ON  — Number of packets: low (tens); Data size: KB–low MB
      OFF — Number of packets: high (tens of thousands); Data size ≈ 2× file

    tshark nfs.opcode (decisive pair):
      ON  — 60 (COPY) present; 25/38 (READ/WRITE) == 0
      OFF — 25/38 (READ/WRITE) flooded
    """
    mode = "ON" if offload_enabled else "OFF"
    announce(
        f"Validate xcopy pcap (Copy_Offload={mode}) via "
        f"tcpdump/capinfos/tshark ({pcap_path})"
    )
    log.info(
        "pcap validate: path=%s file_size_bytes=%s Copy_Offload=%s host=%s",
        pcap_path,
        file_size_bytes,
        mode,
        client.hostname,
    )
    ensure_xcopy_pcap_tools(client)

    out, _ = client.exec_command(sudo=True, cmd=f"capinfos {pcap_path}")
    capinfos_text = (out or "").strip()
    log.info("capinfos %s:\n%s", pcap_path, capinfos_text)
    caps = _parse_capinfos(capinfos_text)
    log.info("Parsed capinfos: %s", caps)

    opcode_cmd = (
        f"tshark -r {pcap_path} -Y nfs -T fields -e nfs.opcode "
        f"| tr ',' '\\n' | sort | uniq -c | sort -nr"
    )
    log.info("Running: %s", opcode_cmd)
    out, _ = client.exec_command(sudo=True, cmd=opcode_cmd, timeout=600)
    opcode_text = (out or "").strip()
    log.info("NFS opcode histogram:\n%s", opcode_text if opcode_text else "<none>")
    opcodes = _parse_opcode_histogram(opcode_text)
    log.info("Parsed opcode counts: %s", opcodes)

    packets = caps.get("packets")
    data_size = caps.get("data_size")
    if packets is None or packets == 0:
        log.error("pcap has no packets (capinfos Number of packets missing/zero)")
        return False
    if data_size is None:
        log.error("Could not parse capinfos Data size")
        return False

    copy_n = _opcode_count(opcodes, NFS_OPCODE_COPY, "COPY")
    read_n = _opcode_count(opcodes, NFS_OPCODE_READ, "READ")
    write_n = _opcode_count(opcodes, NFS_OPCODE_WRITE, "WRITE")
    rw_n = read_n + write_n
    log.info(
        "Decisive opcodes: COPY(60)=%s READ(25)=%s WRITE(38)=%s READ+WRITE=%s",
        copy_n,
        read_n,
        write_n,
        rw_n,
    )

    if offload_enabled:
        # --- Copy_Offload = true ---
        log.info(
            "Expect ON: packets<=%s (tens), data_size<=%s (KB–low MB), "
            "COPY(60)>0, READ+WRITE==%s",
            on_max_packets,
            on_max_data_bytes,
            on_max_rw_ops,
        )
        if packets > on_max_packets:
            log.error(
                "ON: Number of packets=%s exceeds max %s (expected tens)",
                packets,
                on_max_packets,
            )
            return False
        log.info("PASS capinfos packets=%s (ON / tens)", packets)

        if data_size > on_max_data_bytes:
            log.error(
                "ON: Data size=%s exceeds max %s (expected KB–low MB)",
                data_size,
                on_max_data_bytes,
            )
            return False
        log.info("PASS capinfos data_size=%s (ON / KB–low MB)", data_size)

        if copy_n < 1:
            log.error(
                "ON: NFS COPY opcode 60 missing (decisive); saw opcodes=%s", opcodes
            )
            return False
        log.info("PASS tshark COPY(60)=%s present (ON)", copy_n)

        if rw_n > on_max_rw_ops:
            log.error(
                "ON: READ(25)+WRITE(38)=%s (expected %s); not server-side offload",
                rw_n,
                on_max_rw_ops,
            )
            return False
        log.info("PASS tshark READ+WRITE=%s (expected %s)", rw_n, on_max_rw_ops)
    else:
        # --- Copy_Offload = false ---
        log.info(
            "Expect OFF: packets>=%s (tens of thousands), "
            "data_size ≈ 2× file (%s..%s × %s), READ+WRITE>=%s (flood)",
            off_min_packets,
            off_data_ratio_min,
            off_data_ratio_max,
            file_size_bytes,
            off_min_rw_ops,
        )
        if packets < off_min_packets:
            log.error(
                "OFF: Number of packets=%s below min %s (expected tens of thousands)",
                packets,
                off_min_packets,
            )
            return False
        log.info("PASS capinfos packets=%s (OFF / tens of thousands)", packets)

        ratio = float(data_size) / float(file_size_bytes) if file_size_bytes else 0.0
        log.info(
            "Data size ratio check: data_size=%s file_size=%s ratio=%.3f "
            "(expect %.2f..%.2f)",
            data_size,
            file_size_bytes,
            ratio,
            off_data_ratio_min,
            off_data_ratio_max,
        )
        if ratio < off_data_ratio_min or ratio > off_data_ratio_max:
            log.error(
                "OFF: Data size/File size ratio %.3f not ≈ 2× (allowed %.2f..%.2f)",
                ratio,
                off_data_ratio_min,
                off_data_ratio_max,
            )
            return False
        log.info("PASS capinfos data_size ≈ 2× file (ratio=%.3f)", ratio)

        if rw_n < off_min_rw_ops:
            log.error(
                "OFF: READ(25)+WRITE(38)=%s below flood min %s; saw opcodes=%s",
                rw_n,
                off_min_rw_ops,
                opcodes,
            )
            return False
        log.info(
            "PASS tshark READ+WRITE=%s flood (OFF, min %s); COPY(60)=%s",
            rw_n,
            off_min_rw_ops,
            copy_n,
        )

    announce(
        f"PASS pcap validation Copy_Offload={mode}: packets={packets} "
        f"data_size={data_size} COPY={copy_n} READ+WRITE={rw_n}"
    )
    return True


def ganesha_log_line_mark(node, log_path=HOST_GANESHA_LOG):
    """
    Return current byte size of host ganesha.log (post-copy ``tail -c`` mark).

    Uses ``stat`` instead of ``wc -l`` — FULL_DEBUG logs are multi-GB and
    line-counting them is unnecessarily slow.
    """
    log.info("Marking ganesha.log byte offset: %s on %s", log_path, node.hostname)
    out, _ = node.exec_command(sudo=True, cmd=f"stat -c %s {log_path}")
    mark = int((out or "0").strip())
    log.info("ganesha.log byte mark = %s (%s)", mark, log_path)
    return mark


def _grep_log_source(node, source_cmd, patterns=XCOPY_GREP_PATTERNS):
    """
    One cumulative remote grep for all xcopy match strings.

    ``source_cmd`` is a shell fragment that prints the log slice to stdout
    (e.g. ``tail -n +N /var/log/ganesha/ganesha.log`` or ``podman logs ...``).
    Returns matched lines for validators. Grep must find at least one hit.
    """
    # Patterns are static constants; join into a single ERE for one grep.
    ere = "|".join(f"({p})" for p in patterns)
    cmd = f"{source_cmd} | grep -Ei '{ere}'"
    log.info(
        "Cumulative xcopy grep on %s (%s pattern(s)):\n%s",
        node.hostname,
        len(patterns),
        cmd,
    )
    out, _ = node.exec_command(sudo=True, cmd=cmd)
    text = (out or "").rstrip()
    n_lines = len(text.splitlines()) if text else 0
    log.info(
        "Cumulative grep hits on %s (%s line(s)):\n%s",
        node.hostname,
        n_lines,
        text if text else "<none>",
    )
    return text


def collect_host_ganesha_logs(node, log_path=HOST_GANESHA_LOG, from_line=0):
    """
    Grep host ganesha.log bytes after ``from_line`` for xcopy match strings.

    ``from_line`` is a byte offset (from ``ganesha_log_line_mark``), not a
    line number — kept for call-site compatibility.
    """
    start = max(int(from_line), 0) + 1
    log.info(
        "Collect host ganesha logs: path=%s from_byte=%s -> tail -c +%s host=%s",
        log_path,
        from_line,
        start,
        node.hostname,
    )
    source = f"tail -c +{start} {log_path}"
    announce(f"Grep host ganesha.log ({log_path}) for xcopy match strings")
    matched = _grep_log_source(node, source)
    log.info(
        "Collected %s bytes of grepped host ganesha log from %s",
        len(matched),
        node.hostname,
    )
    return matched


def collect_nfs_logs(nfs_nodes, nfs_name=None, since=None):
    """Grep podman NFS logs for xcopy match strings (cephadm / TSM-style)."""
    if not isinstance(nfs_nodes, (list, tuple)):
        nfs_nodes = [nfs_nodes]
    log.info(
        "Collect podman NFS logs: nfs_name=%s since=%s nodes=%s",
        nfs_name,
        since,
        [n.hostname for n in nfs_nodes],
    )
    parts = []
    for node in nfs_nodes:
        cid = get_nfs_container_id(node, nfs_name=nfs_name)
        if not cid:
            log.error("No NFS container on %s", node.hostname)
            continue
        log.info("NFS container on %s: %s", node.hostname, cid)
        node_since = since.get(node.hostname) if isinstance(since, dict) else since
        since_arg = f' --since "{node_since}"' if node_since else ""
        log.info("podman logs since on %s: %s", node.hostname, node_since or "<none>")
        source = f"podman logs{since_arg} {cid} 2>&1"
        announce(f"Grep podman logs on {node.hostname} for xcopy match strings")
        matched = _grep_log_source(node, source)
        log.info(
            "Collected %s bytes of grepped podman logs from %s",
            len(matched),
            node.hostname,
        )
        parts.append(matched)
    combined = "\n".join(parts)
    log.info("Combined podman grepped logs: %s bytes", len(combined))
    return combined


def _expected_chunks(total, chunk_size):
    """Return list of (chunk_idx, src_off, length, progress) for a full copy."""
    chunks = []
    remaining = total
    src_off = 0
    idx = 0
    while remaining > 0:
        length = min(remaining, chunk_size)
        chunks.append((idx, src_off, length, src_off))
        src_off += length
        remaining -= length
        idx += 1
    log.info(
        "Chunk plan: total=%s chunk_size=%s -> %s chunk(s)",
        total,
        chunk_size,
        len(chunks),
    )
    return chunks


def _log_matched_lines(label, log_text, pattern, limit=5):
    """Log up to ``limit`` matching evidence lines from Ganesha output."""
    hits = [ln for ln in (log_text or "").splitlines() if re.search(pattern, ln, re.I)]
    log.info(
        "%s: %s match(es); showing up to %s:\n%s",
        label,
        len(hits),
        limit,
        "\n".join(hits[:limit]) if hits else "<none>",
    )
    return hits


def _validate_xcopy_logs_short_copy(
    log_text,
    file_size_bytes,
    chunk_size_bytes,
    mode="any",
):
    """
    Short_Copy=ON packaging: CB_OFFLOAD after each chunk-sized piece.

    Observed behaviour (multi-chunk file):
      - multiple ASYNC worker jobs / CB_OFFLOAD lines
      - each CB bytes == chunk length (last may be remainder)
      - sum(CB bytes) == file_size
    """
    announce("Validate Short_Copy=ON packaging (per-chunk CB_OFFLOAD)")
    expected = _expected_chunks(int(file_size_bytes), int(chunk_size_bytes))
    expected_n = len(expected)
    announce(
        f"Step: Short_Copy plan — {expected_n} chunk(s), "
        f"expect exactly {expected_n} START / CB_OFFLOAD / mdcache"
    )
    for exp_idx, exp_off, exp_len, _ in expected:
        log.info(
            "  expected piece #%s: src_off=%s len=%s",
            exp_idx,
            exp_off,
            exp_len,
        )

    starts = list(RE_WORKER_START.finditer(log_text))
    log.info(
        "Found %s worker START match(es), expected %s", len(starts), expected_n
    )
    if not starts:
        log.error("Short_Copy: no COPY SYNC|ASYNC worker START in logs")
        return False

    detected = starts[0].group(1).upper()
    logged_chunk = int(starts[0].group(5))
    log.info("Evidence first START:\n%s", starts[0].group(0))
    if mode != "any" and detected.lower() != mode.lower():
        log.error("Expected copy mode %s but logs show %s", mode, detected)
        return False
    log.info("PASS: mode=%s (required=%s)", detected, mode)

    if logged_chunk != int(chunk_size_bytes):
        log.error(
            "Logged chunk_size=%s does not match Copy_Offload_Chunk_Size=%s",
            logged_chunk,
            chunk_size_bytes,
        )
        return False
    log.info("PASS: chunk_size=%s", logged_chunk)

    if len(starts) != expected_n:
        log.error(
            "Short_Copy: found %s worker START(s), expected exactly %s "
            "(one job per chunk)",
            len(starts),
            expected_n,
        )
        return False
    log.info("PASS: worker START count=%s == %s", len(starts), expected_n)

    if detected == "ASYNC":
        announce("Step: ASYNC milestones (offload state / submit / CB_OFFLOAD)")
        state_hits = _log_matched_lines(
            "create_copy_offload_state", log_text, RE_OFFLOAD_STATE.pattern
        )
        if not state_hits:
            log.warning(
                "Short_Copy ASYNC: create_copy_offload_state missing (continuing)"
            )
        else:
            log.info("PASS: create_copy_offload_state present")

        submit_hits = _log_matched_lines(
            "copy_submit_job", log_text, RE_SUBMIT_JOB.pattern
        )
        if not submit_hits:
            log.warning("Short_Copy ASYNC: copy_submit_job missing (continuing)")
        else:
            log.info("PASS: copy_submit_job present")

    cb = list(RE_CB_OFFLOAD.finditer(log_text))
    log.info(
        "Found %s CB_OFFLOAD sending OK match(es), expected %s",
        len(cb),
        expected_n,
    )
    if len(cb) != expected_n:
        log.error(
            "Short_Copy: found %s CB_OFFLOAD, expected exactly %s (one per chunk)",
            len(cb),
            expected_n,
        )
        return False

    cb_sizes = []
    for i, hit in enumerate(cb):
        nbytes = int(hit.group(1))
        cb_sizes.append(nbytes)
        exp_len = expected[i][2]
        log.info("Evidence CB #%s:\n%s", i, hit.group(0))
        if nbytes != exp_len:
            log.error(
                "Short_Copy: CB #%s bytes=%s, expected chunk len=%s",
                i,
                nbytes,
                exp_len,
            )
            return False
        log.info("PASS CB #%s: bytes=%s == chunk len", i, nbytes)

    if sum(cb_sizes) != int(file_size_bytes):
        log.error(
            "Short_Copy: sum(CB bytes)=%s != file_size=%s",
            sum(cb_sizes),
            file_size_bytes,
        )
        return False
    log.info(
        "PASS: sum(CB bytes)=%s == file_size (per-chunk completion, not one final CB)",
        sum(cb_sizes),
    )

    md_hits = list(RE_MDCACHE_OK.finditer(log_text))
    log.info(
        "Found %s mdcache done OK line(s), expected %s",
        len(md_hits),
        expected_n,
    )
    if len(md_hits) != expected_n:
        log.error(
            "Short_Copy: found %s mdcache done OK, expected exactly %s",
            len(md_hits),
            expected_n,
        )
        return False
    for exp_idx, _, exp_len, _ in expected:
        got = int(md_hits[exp_idx].group(1))
        log.info("Evidence mdcache #%s:\n%s", exp_idx, md_hits[exp_idx].group(0))
        if got != exp_len:
            log.error(
                "Short_Copy: mdcache #%s copied=%s, expected %s",
                exp_idx,
                got,
                exp_len,
            )
            return False
        log.info("PASS mdcache #%s: copied=%s", exp_idx, got)

    announce(
        f"PASS Short_Copy log validation: mode={detected} "
        f"file_size={file_size_bytes} chunk_size={logged_chunk} "
        f"cb_count={expected_n}"
    )
    return True


def validate_xcopy_logs(
    log_text,
    file_size_bytes,
    chunk_size_bytes,
    mode="any",
    short_copy=False,
):
    """
    Validate xcopy milestones and chunk arithmetic from Ganesha logs.

    short_copy=False (default, Short_Copy=OFF):
      - one worker START with total == file_size, src_off=dst_off=0
      - chunk #0..N-1 under that job
      - one CB_OFFLOAD with bytes == file_size (ASYNC)

    short_copy=True (Short_Copy=ON):
      - per-chunk completion: exactly N CB_OFFLOAD, each == chunk len
      - sum(CB bytes) == file_size
      - exactly N worker START / mdcache done OK

    mode: sync | async | any
    Returns True on success.
    """
    announce(
        "Validate xcopy milestones + chunk math from Ganesha logs "
        f"(Short_Copy={'ON' if short_copy else 'OFF'})"
    )
    log.info(
        "Inputs: expected_total=%s expected_chunk_size=%s required_mode=%s "
        "short_copy=%s log_bytes=%s",
        file_size_bytes,
        chunk_size_bytes,
        mode,
        short_copy,
        len(log_text or ""),
    )
    if not log_text or not log_text.strip():
        log.error("Empty Ganesha logs; cannot validate xcopy")
        return False

    if short_copy:
        return _validate_xcopy_logs_short_copy(
            log_text,
            file_size_bytes=file_size_bytes,
            chunk_size_bytes=chunk_size_bytes,
            mode=mode,
        )

    announce("Step: find COPY SYNC|ASYNC worker START")
    starts = list(RE_WORKER_START.finditer(log_text))
    log.info("Found %s worker START match(es)", len(starts))
    if not starts:
        log.error("No 'COPY SYNC|ASYNC worker START' line in logs")
        _log_matched_lines("COPY/xcopy hints", log_text, r"COPY |xcopy|CB_OFFLOAD", 20)
        return False

    # Prefer a START whose total matches the full file (Short_Copy=OFF packaging).
    start = None
    for cand in reversed(starts):
        if int(cand.group(2)) == int(file_size_bytes):
            start = cand
            break
    if start is None:
        start = starts[-1]
        log.warning(
            "No worker START with total==file_size; using last START "
            "(total=%s file_size=%s)",
            start.group(2),
            file_size_bytes,
        )
    detected = start.group(1).upper()
    total = int(start.group(2))
    src_off0 = int(start.group(3))
    dst_off0 = int(start.group(4))
    logged_chunk = int(start.group(5))
    log.info("Using worker START match for Short_Copy=OFF path")
    log.info("Evidence line:\n%s", start.group(0))
    log.info(
        "Parsed worker START: mode=%s total=%s src_off=%s dst_off=%s chunk_size=%s",
        detected,
        total,
        src_off0,
        dst_off0,
        logged_chunk,
    )

    announce("Step: check mode / total / chunk_size / start offsets")
    if mode != "any" and detected.lower() != mode.lower():
        log.error("Expected copy mode %s but logs show %s", mode, detected)
        return False
    log.info("PASS: mode=%s (required=%s)", detected, mode)

    if total != int(file_size_bytes):
        log.error(
            "Worker total=%s does not match expected file size=%s",
            total,
            file_size_bytes,
        )
        return False
    log.info("PASS: total=%s == file_size_bytes", total)

    if logged_chunk != int(chunk_size_bytes):
        log.error(
            "Logged chunk_size=%s does not match configured Copy_Offload_Chunk_Size=%s",
            logged_chunk,
            chunk_size_bytes,
        )
        return False
    log.info("PASS: chunk_size=%s == configured Copy_Offload_Chunk_Size", logged_chunk)

    if src_off0 != 0 or dst_off0 != 0:
        log.error("Expected src_off=dst_off=0 at START, got %s/%s", src_off0, dst_off0)
        return False
    log.info("PASS: src_off=0 dst_off=0 at START")

    expected = _expected_chunks(total, logged_chunk)
    expected_n = len(expected)
    announce(
        f"Step: chunk plan — ceil({total}/{logged_chunk}) = {expected_n} chunk(s)"
    )
    for exp_idx, exp_off, exp_len, exp_prog in expected:
        log.info(
            "  expected chunk #%s: src_off=%s len=%s progress=%s/%s",
            exp_idx,
            exp_off,
            exp_len,
            exp_prog,
            total,
        )

    if detected == "ASYNC":
        announce("Step: ASYNC milestones (offload state / submit / CB_OFFLOAD)")
        state_hits = _log_matched_lines(
            "create_copy_offload_state", log_text, RE_OFFLOAD_STATE.pattern
        )
        if not state_hits:
            log.error("ASYNC path missing create_copy_offload_state")
            return False
        log.info("PASS: create_copy_offload_state present")

        submit_hits = _log_matched_lines(
            "copy_submit_job", log_text, RE_SUBMIT_JOB.pattern
        )
        if not submit_hits:
            log.error("ASYNC path missing copy_submit_job")
            return False
        log.info("PASS: copy_submit_job present")

        cb = list(RE_CB_OFFLOAD.finditer(log_text))
        log.info("Found %s CB_OFFLOAD sending OK match(es)", len(cb))
        if not cb:
            log.error("ASYNC path missing CB_OFFLOAD: sending OK")
            return False
        # Short_Copy=OFF: one final CB with bytes == full file size.
        full_cbs = [m for m in cb if int(m.group(1)) == total]
        if not full_cbs:
            log.error(
                "Short_Copy=OFF: no CB_OFFLOAD with bytes==file_size (%s); "
                "saw %s",
                total,
                [int(m.group(1)) for m in cb],
            )
            return False
        log.info("Evidence line:\n%s", full_cbs[-1].group(0))
        log.info(
            "PASS: CB_OFFLOAD bytes=%s == total (single completion at end)",
            total,
        )
    else:
        announce("Step: SYNC milestones (no CB_OFFLOAD required)")
        if RE_CB_OFFLOAD.search(log_text):
            log.warning("SYNC path unexpectedly has CB_OFFLOAD (continuing)")
        else:
            log.info("No CB_OFFLOAD in SYNC path (expected)")
        log.info("PASS: SYNC worker START present")

    announce(f"Step: validate {expected_n} chunk log line(s)")
    chunk_re = re.compile(
        rf"COPY {detected} chunk #(\d+):\s*src_off=(\d+)\s+len=(\d+)\s+"
        rf"progress=(\d+)/(\d+)",
        re.I,
    )
    after = log_text[start.start() :]
    chunk_hits = list(chunk_re.finditer(after))
    log.info("Found %s chunk log line(s), expected %s", len(chunk_hits), expected_n)
    if len(chunk_hits) != expected_n:
        log.error(
            "Found %s chunk log lines, expected exactly %s",
            len(chunk_hits),
            expected_n,
        )
        return False

    for exp_idx, exp_off, exp_len, exp_prog in expected:
        hit = chunk_hits[exp_idx]
        got_idx = int(hit.group(1))
        got_off = int(hit.group(2))
        got_len = int(hit.group(3))
        got_prog = int(hit.group(4))
        got_total = int(hit.group(5))
        log.info("Evidence line:\n%s", hit.group(0))
        if (
            got_idx != exp_idx
            or got_off != exp_off
            or got_len != exp_len
            or got_prog != exp_prog
            or got_total != total
        ):
            log.error(
                "Chunk #%s mismatch: got idx=%s off=%s len=%s prog=%s/%s; "
                "expected idx=%s off=%s len=%s prog=%s/%s",
                exp_idx,
                got_idx,
                got_off,
                got_len,
                got_prog,
                got_total,
                exp_idx,
                exp_off,
                exp_len,
                exp_prog,
                total,
            )
            return False
        log.info(
            "PASS chunk #%s: src_off=%s len=%s progress=%s/%s",
            got_idx,
            got_off,
            got_len,
            got_prog,
            got_total,
        )

    announce("Step: validate mdcache done OK copied= sizes")
    md_hits = list(RE_MDCACHE_OK.finditer(after))
    log.info(
        "Found %s mdcache done OK line(s), expected %s",
        len(md_hits),
        expected_n,
    )
    if len(md_hits) != expected_n:
        log.error(
            "Found %s mdcache done OK lines, expected exactly %s",
            len(md_hits),
            expected_n,
        )
        return False
    for exp_idx, _, exp_len, _ in expected:
        got = int(md_hits[exp_idx].group(1))
        log.info("Evidence line:\n%s", md_hits[exp_idx].group(0))
        if got != exp_len:
            log.error(
                "mdcache done OK copied=%s for chunk #%s, expected %s",
                got,
                exp_idx,
                exp_len,
            )
            return False
        log.info("PASS mdcache chunk #%s: copied=%s", exp_idx, got)

    announce(
        f"PASS xcopy log validation: mode={detected} total={total} "
        f"chunk_size={logged_chunk} chunks={expected_n} Short_Copy=OFF"
    )
    log.info(
        "xcopy validation summary: mode=%s total=%s chunk_size=%s chunks=%s "
        "short_copy=False",
        detected,
        total,
        logged_chunk,
        expected_n,
    )
    return True


def verify_copy_offload_logs(
    nfs_nodes,
    nfs_name,
    file_size_bytes,
    chunk_size_bytes,
    since=None,
    mode="any",
    community=False,
    ganesha_log_path=HOST_GANESHA_LOG,
    log_from_line=0,
    short_copy=False,
):
    """
    Collect logs and validate xcopy milestones + chunk math.

    community=True  -> ``/var/log/ganesha/ganesha.log`` on the Ganesha host
    community=False -> podman logs (cephadm), same pattern as TSM helpers
    short_copy      -> Short_Copy=ON per-chunk CB packaging vs OFF single CB
    """
    log.info(
        "verify_copy_offload_logs: community=%s nfs_name=%s mode=%s "
        "short_copy=%s file_size_bytes=%s chunk_size_bytes=%s since=%s "
        "log_from_line=%s",
        community,
        nfs_name,
        mode,
        short_copy,
        file_size_bytes,
        chunk_size_bytes,
        since,
        log_from_line,
    )
    if community:
        node = nfs_nodes[0] if isinstance(nfs_nodes, (list, tuple)) else nfs_nodes
        announce(
            f"Collect host Ganesha logs: {ganesha_log_path} "
            f"from byte {log_from_line}+ on {node.hostname}"
        )
        text = collect_host_ganesha_logs(
            node, log_path=ganesha_log_path, from_line=log_from_line
        )
        log.info(
            "Collected %s bytes / %s lines from %s",
            len(text),
            text.count("\n") + (1 if text and not text.endswith("\n") else 0),
            ganesha_log_path,
        )
    else:
        announce(f"Collect podman NFS logs for cluster {nfs_name} (since={since})")
        text = collect_nfs_logs(nfs_nodes, nfs_name=nfs_name, since=since)
        log.info("Collected %s bytes of podman logs", len(text))

    ok = validate_xcopy_logs(
        text,
        file_size_bytes=file_size_bytes,
        chunk_size_bytes=chunk_size_bytes,
        mode=mode,
        short_copy=short_copy,
    )
    log.info("verify_copy_offload_logs result: %s", "PASS" if ok else "FAIL")
    return ok
