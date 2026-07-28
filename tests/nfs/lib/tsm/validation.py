"""Validate NFS-Ganesha TSM configuration, listen port, and peer connectivity."""

import json

from ceph.waiter import WaitUntil
from cli.ceph.ceph import Ceph
from cli.exceptions import OperationFailedError
from tests.nfs.lib.common_lib import (
    assert_port_listening,
    read_ganesha_conf,
    scrape_nfs_logs,
)
from utility.log import Log

log = Log(__name__)


class NfsTsmValidation:
    """Post-deploy TSM checks against orch daemons and ganesha.conf."""

    def __init__(
        self,
        ceph_cluster,
        client,
        enable_tsm_key,
        tsm_port_key,
        tsm_port,
        timeout=30,
        poll_interval=5,
    ):
        self.ceph_cluster = ceph_cluster
        self.client = client
        self.installer = ceph_cluster.get_nodes("installer")[0]
        self.enable_tsm_key = enable_tsm_key
        self.tsm_port_key = tsm_port_key
        self.tsm_port = tsm_port
        self.timeout = timeout
        self.poll_interval = poll_interval

    def get_cluster_info(self, nfs_name):
        info = Ceph(self.client).nfs.cluster.info(nfs_name)
        if not info or nfs_name not in info:
            raise OperationFailedError(
                f"Cluster {nfs_name!r} not found in nfs cluster info: {info!r}"
            )
        log.info("NFS cluster info for %s:\n%s", nfs_name, json.dumps(info, indent=2))
        return info[nfs_name]

    def assert_ganesha_tsm_conf(
        self,
        nfs_name,
        nfs_nodes,
        expect_enabled=True,
        expected_tsm_port=None,
    ):
        """Verify enable_TSM and Tsm_Port in ganesha.conf on each NFS node."""
        log.info("GANESHA.CONF TSM VALIDATION")
        conf_by_host = read_ganesha_conf(nfs_nodes, nfs_name=nfs_name)
        expected_port = str(
            self.tsm_port if expected_tsm_port is None else expected_tsm_port
        )
        expected_enabled = "true" if expect_enabled else "false"
        results = []

        for node in nfs_nodes:
            conf = conf_by_host.get(node.hostname)
            if not conf:
                raise OperationFailedError(f"No ganesha.conf for {node.hostname}")

            core = conf.get("NFS_CORE_PARAM", {})
            enabled = str(core.get(self.enable_tsm_key, "")).lower()
            tsm_port = str(core.get(self.tsm_port_key, ""))
            peers = [
                p.strip()
                for p in conf.get("CEPH_NODES_LIST", {})
                .get("Ceph_Nodes", "")
                .split(",")
                if p.strip()
            ]
            log.info(
                "%s: %s=%s %s=%s peers=%s",
                node.hostname,
                self.enable_tsm_key,
                enabled,
                self.tsm_port_key,
                tsm_port,
                peers,
            )

            if enabled != expected_enabled:
                raise OperationFailedError(
                    f"{node.hostname}: expected {self.enable_tsm_key}={expected_enabled}, "
                    f"got {enabled!r}"
                )
            if tsm_port != expected_port:
                raise OperationFailedError(
                    f"{node.hostname}: expected {self.tsm_port_key}={expected_port}, "
                    f"got {tsm_port!r}"
                )

            results.append(
                {
                    "hostname": node.hostname,
                    "node": node,
                    "enabled": enabled == "true",
                    "tsm_port": tsm_port,
                    "peers": peers,
                    "conf": conf,
                }
            )
        return results

    def assert_tsm_peer_connections(
        self, nodes, tsm_port=None, timeout=None, min_peers=1
    ):
        """Wait until each node has ESTAB TCP sessions to peer IPs on TSM port."""
        port = int(tsm_port if tsm_port is not None else self.tsm_port)
        timeout = self.timeout if timeout is None else timeout
        ips = {node.hostname: node.ip_address for node in nodes}

        for node in nodes:
            peers = [ip for host, ip in ips.items() if host != node.hostname and ip]
            if len(peers) < min_peers:
                raise OperationFailedError(
                    f"{node.hostname}: need >= {min_peers} peers, got {peers}"
                )

            for _ in WaitUntil(timeout=timeout, interval=self.poll_interval):
                out, _ = node.exec_command(
                    sudo=True,
                    cmd=(
                        f"ss -tnp state established "
                        f"'( sport = :{port} or dport = :{port} )'"
                    ),
                    check_ec=False,
                )
                if sum(ip in (out or "") for ip in peers) >= min_peers:
                    log.info("%s: TSM ESTAB peers ok -> %s", node.hostname, peers)
                    break
            else:
                raise OperationFailedError(
                    f"{node.hostname}: timed out waiting for TSM ESTAB to {peers} "
                    f"on port {port}"
                )

    def assert_tsm_ready(
        self,
        nfs_name,
        nfs_nodes,
        tsm_port=None,
        expect_enabled=True,
        timeout=None,
        check_peers=True,
        log_patterns=("Enabling tsm",),
        log_since=None,
    ):
        """Composite ready check: conf → port listen → logs → optional peer ESTAB."""
        log.info("ASSERT TSM READY (%s)", nfs_name)
        port = self.tsm_port if tsm_port is None else tsm_port
        timeout = self.timeout if timeout is None else timeout
        for _ in WaitUntil(timeout=timeout, interval=self.poll_interval):
            try:
                conf = self.assert_ganesha_tsm_conf(
                    nfs_name, nfs_nodes, expect_enabled=expect_enabled,
                    expected_tsm_port=port,
                )
                if expect_enabled:
                    assert_port_listening(nfs_nodes, port, label="TSM port")
                    if log_patterns:
                        scrape_nfs_logs(
                            nfs_nodes,
                            log_patterns,
                            nfs_name=nfs_name,
                            require_match=True,
                            since=log_since,
                        )
                break
            except OperationFailedError as exc:
                log.warning("TSM not ready yet: %s", exc)
        else:
            raise OperationFailedError(
                f"TSM ready check did not succeed within {timeout}s for nfs.{nfs_name}"
            )
        if expect_enabled and check_peers and len(conf) >= 2:
            self.assert_tsm_peer_connections(
                [e["node"] for e in conf], tsm_port=port
            )
        return conf
