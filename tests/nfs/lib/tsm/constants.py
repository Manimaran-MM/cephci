"""TSM boot-path log markers for first-boot vs recovery validation."""

# ---------------------------------------------------------------------------
# First-boot path (initial orch apply / NFS bring-up)
# INFO-level markers visible before COMPONENT_TSM debug is enabled.
# Bring-up (assert_tsm_boot_logs / assert_tsm_ready) checks PRESENT only.
# ABSENT is reserved for stricter path discrimination if needed elsewhere —
# do not use it on cold start (reaper may log "Got back the primary..." after
# peer selection without that being a recovery-path boot).
# ---------------------------------------------------------------------------
TSM_FIRST_BOOT_PRESENT = (
    "TSM thread is initialized",
    "TSM_PEER_RECORD_FIRST_BOOT_DONE",
    "Total cluster size",
)

TSM_FIRST_BOOT_ABSENT = (
    r"TSM_PEER_RECORD_RECOVERY_DONE|"
    r"Full recovery successful|"
    r"Got back the primary and secondary|"
    r"GET_STATE ACK completed|"
    r"TSM_PEER_RECORD_RECOVERY_FAILED|"
    r"TSM_DISABLE_NOTIFY|"
    r"Cleaned all node state|"
    r"Disabling tsm: No primary"
)

# ---------------------------------------------------------------------------
# Recovery path (peers already had primary/secondary)
# ---------------------------------------------------------------------------
TSM_RECOVERY_PRESENT = (
    r"TSM_PEER_RECORD_RECOVERY_DONE|"
    r"Full recovery successful|"
    r"Got back the primary and secondary|"
    r"GET_STATE ACK completed"
)

TSM_RECOVERY_ABSENT = (
    r"TSM_PEER_RECORD_FIRST_BOOT_DONE|"
    r"Broadcasting TSM_PEER_IP_NOTIFY|"
    r"Signalling Peer ping|"
    r"Received peer ping ACK|"
    r"TSM_PEER_RECORD_RECOVERY_FAILED|"
    r"TSM_DISABLE_NOTIFY|"
    r"Cleaned all node state|"
    r"Disabling tsm: No primary"
)

# ---------------------------------------------------------------------------
# Disable path (state retrieval failed)
# Peers: OR of notify/cleanup strings (TSM_DISABLE_PEER_PRESENT as one regex).
# Recovering node: only ABSENT checks (no required local PRESENT markers).
# Note: with peer INPUT DROP, notify may not arrive until partition is lifted /
# fault model allows delivery.
# ---------------------------------------------------------------------------
TSM_DISABLE_PRESENT = ()

TSM_DISABLE_PEER_PRESENT = (
    r"Cleaned all node state records|TSM_DISABLE_NOTIFY",
)

TSM_DISABLE_ABSENT = (
    "Full recovery successful",
    "TSM_PEER_RECORD_RECOVERY_DONE",
)

# ---------------------------------------------------------------------------
# Primary-selection / all-peers-down path (joining node alone after max retries)
# Each marker below must match individually (not OR'd).
# ---------------------------------------------------------------------------
TSM_PRIMARY_SELECTION_FAIL_PRESENT = (
    "Peer recovery failed after 5 attempts",
    "TSM_PEER_RECORD_RECOVERY_FAILED",
)

TSM_PRIMARY_SELECTION_FAIL_ABSENT = (
    "Full recovery successful",
    "TSM_PEER_RECORD_RECOVERY_DONE",
    "Primary index",
    "Secondary index",
)


class NfsFcntlLock:
    """Build fcntl(F_SETLKW) hold commands; SIGTERM runs matching F_UNLCK."""

    @staticmethod
    def _mode_flags(mode):
        """Return (os.open flags expr, whether to seed empty file)."""
        if mode == "r":
            return "os.O_RDONLY", False
        if mode == "r+":
            return "os.O_RDWR", False
        # w+: create if missing and ensure non-empty for lock IO
        return "os.O_RDWR|os.O_CREAT", True

    @staticmethod
    def _hold_cmd(path, lock_type, start=0, length=0, flags="os.O_RDWR|os.O_CREAT", seed=False):
        """Hold lock until SIGTERM/SIGINT → explicit F_UNLCK then close."""
        if "O_CREAT" in flags:
            open_stmt = f"fd=os.open(path,{flags},0o644);"
        else:
            open_stmt = f"fd=os.open(path,{flags});"
        seed_stmt = (
            "os.write(fd,b'x'*4096) if os.fstat(fd).st_size==0 else None;"
            if seed
            else ""
        )
        # length 0 == whole file (POSIX); else byte-range
        return (
            "python3 -c \""
            "import fcntl,os,struct,signal,sys;"
            f"path='{path}';start={int(start)};length={int(length)};"
            "pack=lambda t:struct.pack('hhqqq',t,os.SEEK_SET,start,length,0);"
            f"{open_stmt}"
            f"{seed_stmt}"
            f"fcntl.fcntl(fd,fcntl.F_SETLKW,pack({lock_type}));"
            "print('LOCKED pid=%s'%os.getpid(),flush=True);"
            "u=lambda *a:(fcntl.fcntl(fd,fcntl.F_SETLK,pack(fcntl.F_UNLCK)),"
            "print('UNLOCKED',flush=True),os.close(fd),sys.exit(0));"
            "signal.signal(signal.SIGTERM,u);signal.signal(signal.SIGINT,u);"
            "signal.pause()\""
        )

    @staticmethod
    def shared_hold(path, mode="r"):
        flags, seed = NfsFcntlLock._mode_flags(mode)
        return NfsFcntlLock._hold_cmd(
            path, "fcntl.F_RDLCK", start=0, length=0, flags=flags, seed=seed
        )

    @staticmethod
    def exclusive_hold(path, mode="w+"):
        flags, seed = NfsFcntlLock._mode_flags(mode)
        return NfsFcntlLock._hold_cmd(
            path, "fcntl.F_WRLCK", start=0, length=0, flags=flags, seed=seed
        )

    @staticmethod
    def byte_range_hold(path, length, start=0, shared=False):
        lock = "fcntl.F_RDLCK" if shared else "fcntl.F_WRLCK"
        return NfsFcntlLock._hold_cmd(
            path,
            lock,
            start=start,
            length=length,
            flags="os.O_RDWR|os.O_CREAT",
            seed=True,
        )

    @staticmethod
    def exclusive_then_unlock_hold(path, hold_secs=8):
        """F_WRLCK, hold briefly, F_UNLCK, keep FD open (unlock-without-close)."""
        return (
            "python3 -c \""
            "import fcntl,os,struct,signal,time,sys;"
            f"path='{path}';start=0;length=0;"
            "pack=lambda t:struct.pack('hhqqq',t,os.SEEK_SET,start,length,0);"
            "fd=os.open(path,os.O_RDWR|os.O_CREAT,0o644);"
            "os.write(fd,b'x'*4096) if os.fstat(fd).st_size==0 else None;"
            "fcntl.fcntl(fd,fcntl.F_SETLKW,pack(fcntl.F_WRLCK));"
            "print('LOCKED pid=%s'%os.getpid(),flush=True);"
            f"time.sleep({int(hold_secs)});"
            "fcntl.fcntl(fd,fcntl.F_SETLK,pack(fcntl.F_UNLCK));"
            "print('UNLOCKED',flush=True);"
            "u=lambda *a:(os.close(fd),sys.exit(0));"
            "signal.signal(signal.SIGTERM,u);signal.signal(signal.SIGINT,u);"
            "signal.pause()\""
        )

    @staticmethod
    def read_at_offset_hold(path, offset, length=100):
        """Read unlocked range and keep FD open (no lock)."""
        return (
            "python3 -c \""
            "import os,signal,sys;"
            f"fd=os.open('{path}',os.O_RDONLY);"
            f"os.lseek(fd,{int(offset)},0);"
            f"os.read(fd,{int(length)});"
            "u=lambda *a:(os.close(fd),sys.exit(0));"
            "signal.signal(signal.SIGTERM,u);signal.signal(signal.SIGINT,u);"
            "signal.pause()\""
        )

    @staticmethod
    def kill_pid(client, pid):
        if not pid:
            return
        client.exec_command(
            sudo=True,
            cmd=f"kill {pid} 2>/dev/null",
            check_ec=False,
        )

