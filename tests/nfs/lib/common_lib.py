"""Common NFS helpers shared across feature libs/tests."""

import re
from datetime import datetime

from cli.exceptions import OperationFailedError
from utility.log import Log

log = Log(__name__)


def read_ganesha_conf(nodes, nfs_name=None):
    """
    Cat and parse ganesha.conf on one or more NFS nodes.

    Returns nested dict keyed by hostname -> block -> key (string values):
      {
        "node1": {
          "NFS_CORE_PARAM": {"enable_TSM": "true", "Tsm_Port": "36369", ...},
          "CEPH_NODES_LIST": {"Ceph_Nodes": "10.0.65.251, 10.0.66.195"},
          ...
        }
      }
    """
    if not isinstance(nodes, (list, tuple)):
        nodes = [nodes]

    result = {}
    for node in nodes:
        pattern = f"/var/lib/ceph/*/nfs.{nfs_name}*/etc/ganesha/ganesha.conf"
        if not nfs_name:
            pattern = "/var/lib/ceph/*/nfs.*/etc/ganesha/ganesha.conf"
        out, _ = node.exec_command(
            sudo=True, cmd=f"cat {pattern} 2>/dev/null", check_ec=False
        )
        if not out:
            raise OperationFailedError(
                f"Unable to read ganesha.conf on {node.hostname}"
            )

        conf = {}
        for block, body in re.findall(
            r"([A-Za-z_][\w]*)\s*\{([^}]*)\}", out, flags=re.DOTALL
        ):
            conf[block] = {
                key: raw.strip().strip("\"'")
                for key, raw in re.findall(r"(\w+)\s*=\s*([^;]+);", body)
            }

        log.info("ganesha.conf on %s: %s", node.hostname, conf)
        result[node.hostname] = conf
    return result


def get_nfs_container_id(node, nfs_name=None):
    """
    Return the NFS Ganesha container id on a node.

    Args:
        node: NFS host node.
        nfs_name: Optional cluster/service id filter (e.g. cephfs-nfs).
    """
    match = f"nfs.{nfs_name}" if nfs_name else "nfs."
    out, _ = node.exec_command(
        sudo=True,
        cmd=(
            "podman ps --format '{{.ID}} {{.Names}}' "
            f"| awk '/{match}/ {{print $1; exit}}'"
        ),
        check_ec=False,
    )
    cid = (out or "").strip()
    if not cid:
        raise OperationFailedError(
            f"No NFS container matching {match!r} on {node.hostname}"
        )
    log.info("NFS container on %s: %s", node.hostname, cid)
    return cid


def assert_port_listening(nodes, port, label="port"):
    """Assert TCP/UDP port is listening on one or more nodes."""
    if not isinstance(nodes, (list, tuple)):
        nodes = [nodes]
    port = int(port)
    for node in nodes:
        out, _ = node.exec_command(
            sudo=True,
            cmd=f"ss -H -tulpn sport = :{port}",
            check_ec=False,
        )
        if not (out or "").strip():
            raise OperationFailedError(
                f"{label} {port} is not listening on {node.hostname}"
            )
        log.info("%s %s listening on %s", label, port, node.hostname)


def get_node_time(nodes):
    """Return (log_since, coredump_since) from node(s).

    log_since: {hostname: utc RFC3339 str} for ``podman logs --since``
    coredump_since: {hostname: local datetime} for ``check_coredump_generated``
    """
    if not isinstance(nodes, (list, tuple)):
        nodes = [nodes]
    log_since, coredump_since = {}, {}
    for node in nodes:
        out, _ = node.exec_command(
            sudo=True,
            cmd="date -u +%Y-%m-%dT%H:%M:%SZ; date +'%Y-%m-%d %H:%M:%S'",
        )
        lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
        utc, local = lines[0], lines[1]
        log_since[node.hostname] = utc
        coredump_since[node.hostname] = datetime.strptime(local, "%Y-%m-%d %H:%M:%S")
        log.info("Node time on %s: utc=%s local=%s", node.hostname, utc, local)
    return log_since, coredump_since


def enable_nfs_debug_logs(client, nfs_name, components, conf_file="nfs_debug.conf"):
    """Enable FULL_DEBUG for LOG COMPONENTS key(s) via cluster config set.

    ``components`` may be a string or a list/tuple of component names
    (e.g. ``\"TSM\"`` or ``[\"TSM\", \"STATE\"]``).
    """
    if isinstance(components, str):
        components = [components]
    else:
        components = list(components)
    lines = "\n".join(f"\t{c} = FULL_DEBUG;" for c in components)
    body = f"LOG {{\n    COMPONENTS {{\n{lines}\n    }}\n}}\n"
    conf = client.remote_file(sudo=True, file_name=conf_file, file_mode="w")
    conf.write(body)
    conf.flush()
    out, _ = client.exec_command(sudo=True, cmd=f"cat {conf_file}")
    log.info("NFS debug conf %s:\n%s", conf_file, (out or "").strip())
    client.exec_command(
        sudo=True, cmd=f"ceph nfs cluster config set {nfs_name} -i {conf_file}"
    )
    log.info("Enabled FULL_DEBUG for %s on nfs.%s", components, nfs_name)


def scrape_nfs_logs(
    nodes, patterns, nfs_name=None, tail=80, require_match=False, since=None
):
    """Grep NFS container logs for pattern(s). Returns {hostname: text}.

    ``since`` is passed to ``podman logs --since``. Use a string for all nodes,
    or a {hostname: ts} dict from ``get_node_time``'s log_since (preferred for multi-node).
    """
    if not isinstance(nodes, (list, tuple)):
        nodes = [nodes]
    if isinstance(patterns, str):
        patterns = (patterns,)
    pattern_re = "|".join(re.escape(p) for p in patterns)
    collected = {}
    for node in nodes:
        node_since = since.get(node.hostname) if isinstance(since, dict) else since
        since_arg = f' --since "{node_since}"' if node_since else ""
        cid = get_nfs_container_id(node, nfs_name=nfs_name)
        out, _ = node.exec_command(
            sudo=True,
            cmd=f"podman logs{since_arg} {cid} 2>&1",
            check_ec=False,
        )
        log.info(
            "NFS container logs on %s (since=%s):\n%s",
            node.hostname,
            node_since or "all",
            (out or "").strip() or "<none>",
        )
        matched = [
            line
            for line in (out or "").splitlines()
            if re.search(pattern_re, line, re.I)
        ]
        text = "\n".join(matched[-int(tail) :])
        collected[node.hostname] = text
        log.info("NFS log matches on %s:\n%s", node.hostname, text or "<none>")
        if require_match and not all(p.lower() in text.lower() for p in patterns):
            raise OperationFailedError(
                f"{node.hostname}: patterns {patterns} not found in NFS logs"
            )
    return collected
