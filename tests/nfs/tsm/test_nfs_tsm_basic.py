"""NFS TSM basic enablement — multi-daemon deploy via orch spec."""

import time

from cli.ceph.ceph import Ceph
from cli.exceptions import ConfigError, OperationFailedError
from cli.utilities.filesys import Mount
from cli.utilities.utils import check_coredump_generated
from tests.nfs.lib.common_lib import enable_nfs_debug_logs, get_node_time
from tests.nfs.lib.multi_active.config import NfsMultiActiveConfig
from tests.nfs.lib.tsm import NfsTsmValidation
from tests.nfs.nfs_operations import cleanup_cluster, create_nfs_via_file_and_verify
from utility.log import Log

log = Log(__name__)

COREDUMP_PATH = "/var/lib/systemd/coredump"


def run(ceph_cluster, **kw):
    """
    Deploy a multi-node NFS cluster via orch spec and verify TSM:
      - enable_TSM / Tsm_Port in ganesha.conf on every daemon
      - Tsm_Port is listening
      - 'Enabling tsm' present in daemon logs
      - at least one ESTAB TSM peer connection per host
      - no NFS coredumps after IO
    """
    nfs_nodes = ceph_cluster.get_nodes("nfs")
    clients = ceph_cluster.get_nodes("client")
    installer = ceph_cluster.get_nodes("installer")[0]

    port = "2049"
    version = "4.2"
    nfs_name = "cephfs-nfs"
    nfs_mount = "/mnt/nfs"
    nfs_export = "/export"
    fs_name = "cephfs"
    tsm_port = 36369
    nfs_count = 2
    timeout = 300

    if len(nfs_nodes) < nfs_count:
        raise ConfigError(
            f"TSM basic test needs {nfs_count} NFS nodes, found {len(nfs_nodes)}"
        )
    if not clients:
        raise ConfigError("At least one client node is required")

    nfs_nodes = sorted(nfs_nodes, key=lambda node: node.hostname)[:nfs_count]
    hosts = [node.hostname for node in nfs_nodes]
    clients = clients[:1]

    nfs_spec = {
        "service_type": "nfs",
        "service_id": nfs_name,
        "placement": {"count": nfs_count, "hosts": hosts},
        "spec": {
            "port": int(port),
            "enable_tsm": True,
            "tsm_port": tsm_port,
        },
    }

    try:
        log_since, coredump_since = get_node_time(nfs_nodes)
        log.info("Deploying NFS TSM cluster via orch spec: %s", nfs_spec)
        if not create_nfs_via_file_and_verify(
            installer, [nfs_spec], timeout, nfs_nodes=nfs_nodes
        ):
            raise OperationFailedError("Failed to deploy NFS TSM cluster via spec")

        enable_nfs_debug_logs(clients[0], nfs_name, "TSM")
        time.sleep(3)

        validator = NfsTsmValidation(
            ceph_cluster,
            clients[0],
            enable_tsm_key="enable_TSM",
            tsm_port_key="Tsm_Port",
            tsm_port=tsm_port,
        )

        validator.assert_tsm_ready(
            nfs_name,
            nfs_nodes,
            expect_enabled=True,
            check_peers=True,
            log_patterns=None,
            log_since=log_since,
        )

        Ceph(clients[0]).nfs.export.create(
            fs_name=fs_name,
            nfs_name=nfs_name,
            nfs_export=nfs_export,
            fs=fs_name,
        )
        NfsMultiActiveConfig.wait_until_export_visible(
            clients[0], nfs_name, nfs_export
        )

        clients[0].create_dirs(dir_path=nfs_mount, sudo=True)
        if Mount(clients[0]).nfs(
            mount=nfs_mount,
            version=version,
            port=port,
            server=hosts[0],
            export=nfs_export,
        ):
            raise OperationFailedError(f"Failed to mount nfs on {clients[0].hostname}")

        clients[0].exec_command(
            sudo=True,
            cmd=f"bash -c 'echo tsm-basic > {nfs_mount}/tsm_basic.txt && "
            f"cat {nfs_mount}/tsm_basic.txt'",
        )

        for nfs_node in nfs_nodes:
            if check_coredump_generated(
                nfs_node, COREDUMP_PATH, coredump_since[nfs_node.hostname]
            ):
                raise OperationFailedError(
                    f"Coredump generated on {nfs_node.hostname} during TSM basic test"
                )
        log.info("No NFS coredumps detected after IO")

        log.info("TSM basic enablement and IO succeeded on cluster %s", nfs_name)
        return 0
    except (ConfigError, OperationFailedError) as exc:
        log.error("TSM basic test failed: %s", exc)
        return 1
    except Exception as exc:
        log.exception("Unexpected failure in TSM basic test: %s", exc)
        return 1
    finally:
        cleanup_cluster(clients, nfs_mount, nfs_name, nfs_export, nfs_nodes=nfs_nodes)
