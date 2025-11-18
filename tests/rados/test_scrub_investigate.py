"""
Module to verify libcephsqlite's ability to reopen a database connection if
current connection is down/blocklisted.
"""

import random
import time

from ceph.ceph_admin import CephAdmin
from ceph.rados.core_workflows import RadosOrchestrator
from tests.rados.monitor_configurations import MonConfigMethods
from utility.log import Log

log = Log(__name__)


def run(ceph_cluster, **kw):
    """
    # CEPH-83583664
    Covers:
        - BZ-2130867
        - BZ-2248719
    Test to verify reopening of database connection in case of database blocklisting
    MGR module - libcephsqlite and devicehealth
    Steps
    1. Deploy a ceph cluster
    2. Find the active client address and nonce of libcephsqlite from ceph mgr dump
    3. Choose an OSD at random and get the device id using osd metadata
    4. Run a ceph device command to invoke device health module and utilize libcephsqlite
    5. Capture the value of libcephsqlite address and nonce, should be same as before
    6. Enable logging to file and set debug level for mgr and debug_cephsqlite
    7. Add the MGR address/nonce to OSD blocklist
    8. Run the ceph device command again, should NOT result in an error as a new connection
     should automatically be established with libcephsqlite realizes that current active connection was down.
    9. Capture the value of libcephsqlite address and nonce, nonce should NOT be same as before
    10. Check MGR health status and cluster health
    """
    log.info(run.__doc__)
    config = kw["config"]
    cephadm = CephAdmin(cluster=ceph_cluster, **config)
    rados_obj = RadosOrchestrator(node=cephadm)
    log.info(
        "Running test case to verify reopening of database connection in case of database blocklisting"
    )

    try:
        sleep_duration = config["sleep-duration"]
        log.info("Sleeping for %s seconds" % sleep_duration)
        time.sleep(sleep_duration)

        log.info("Sleep complete")
    except Exception as e:
        log.error(f"Failed with exception: {e.__doc__}")
        log.exception(e)
        # log cluster health
        rados_obj.log_cluster_health()
        return 1
    finally:
        log.info(
            "\n \n ************** Execution of finally block begins here *************** \n \n"
        )
        # log cluster health
        rados_obj.log_cluster_health()
        # check for crashes after test execution
        if rados_obj.check_crash_status():
            log.error("Test failed due to crash at the end of test")
            return 1

    log.info("Verification of Database reconnection for libcephsqlite completed")
    return 0
