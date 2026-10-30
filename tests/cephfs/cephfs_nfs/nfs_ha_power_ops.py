"""Power control helpers for NFS-HA tests (IPMI baremetal or OpenStack VM)."""

from ceph.ceph import CommandFailed
from ceph.utils import find_vm_node_by_hostname
from utility.baremetal_power_ops import IPMIPowerControl
from utility.log import Log
from utility.utils import get_cephci_config

log = Log(__name__)


def get_baremetal_creds():
    """Return (username, password) when configured; otherwise (None, None)."""
    baremetal_creds = get_cephci_config().get("baremetal") or {}
    username = baremetal_creds.get("username")
    password = baremetal_creds.get("password")
    if username and password:
        return username, password
    return None, None


def _hostname(node):
    return node.node.hostname if hasattr(node, "node") else node.hostname


def power_down(ceph_cluster, node, username=None, password=None):
    """Power off a host via IPMI when creds exist, else OpenStack VM shutdown."""
    hostname = _hostname(node)
    if username and password:
        log.info(f"Powering Off {hostname} via IPMI")
        IPMIPowerControl(
            host=f"{hostname}.ipmi.ceph.redhat.com",
            username=username,
            password=password,
        ).power_down()
        return
    log.info(f"Powering Off {hostname} via OpenStack VM shutdown")
    target = find_vm_node_by_hostname(ceph_cluster, hostname)
    if not target:
        raise CommandFailed(
            f"No baremetal credentials and unable to find VM node for {hostname}"
        )
    target.shutdown(wait=True)


def power_up(ceph_cluster, node, username=None, password=None):
    """Power on a host via IPMI when creds exist, else OpenStack VM power_on."""
    hostname = _hostname(node)
    if username and password:
        log.info(f"Powering On {hostname} via IPMI")
        IPMIPowerControl(
            host=f"{hostname}.ipmi.ceph.redhat.com",
            username=username,
            password=password,
        ).power_up()
        return
    log.info(f"Powering On {hostname} via OpenStack VM power_on")
    target = find_vm_node_by_hostname(ceph_cluster, hostname)
    if not target:
        raise CommandFailed(
            f"No baremetal credentials and unable to find VM node for {hostname}"
        )
    target.power_on()
