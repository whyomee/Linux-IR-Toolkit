"""Central detection-rule catalog.

Collectors never invent severity, rationale or remediation text.  They call
``FindingsFactory.create(rule_id, ...)`` and the catalog supplies the analyst
context.  This keeps detections auditable and consistent across modules, and
makes it impossible for a collector to silently mislabel a finding.

Each rule documents:

* **why** - the reasoning behind the detection,
* **false_positives** - legitimate explanations an analyst must exclude,
* **remediation** - defensive guidance, never automatic action.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from irkit.models import Confidence, Severity


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    category: str
    severity: Severity
    why: str
    false_positives: tuple[str, ...]
    remediation: str
    mitre: tuple[str, ...] = ()
    confidence: Confidence = Confidence.MEDIUM


def _rule(
    rule_id: str,
    title: str,
    category: str,
    severity: Severity,
    why: str,
    false_positives: tuple[str, ...],
    remediation: str,
    mitre: tuple[str, ...] = (),
    confidence: Confidence = Confidence.MEDIUM,
) -> Rule:
    return Rule(
        rule_id=rule_id,
        title=title,
        category=category,
        severity=severity,
        why=why,
        false_positives=false_positives,
        remediation=remediation,
        mitre=mitre,
        confidence=confidence,
    )


_RULES: list[Rule] = [
    # ------------------------------------------------------------------ system
    _rule(
        "SYS_KERNEL_TAINTED",
        "Kernel is tainted",
        "system",
        Severity.LOW,
        "The kernel taint flag in /proc/sys/kernel/tainted is non-zero. Taint bits are set by "
        "proprietary or out-of-tree modules, forced module loads, staging drivers, or kernel "
        "warnings and oopses. A tainted kernel means the running kernel is not in a pristine "
        "state, which weakens the trustworthiness of other observations.",
        (
            "NVIDIA, VirtualBox, VMware and some Wi-Fi drivers legitimately taint the kernel.",
            "Some container hosts and cloud images ship out-of-tree modules by design.",
        ),
        "Decode the taint value (Documentation/admin-guide/tainted-kernels.rst), confirm each "
        "taint source against the expected driver inventory, and rebuild/reboot into a "
        "supported kernel if an unexpected module is present.",
        ("T1014",),
        Confidence.HIGH,
    ),
    _rule(
        "SYS_HOSTNAME_MISMATCH",
        "Runtime hostname differs from /etc/hostname",
        "system",
        Severity.LOW,
        "The hostname reported by the kernel differs from the static value in /etc/hostname. "
        "Attackers sometimes rename a host to blend into an environment or to mislead "
        "responders, and the mismatch also complicates evidence correlation.",
        (
            "Cloud-init or DHCP may set a transient hostname without updating /etc/hostname.",
            "Containers routinely inherit a host-assigned hostname.",
            "An administrator may have changed the hostname at runtime.",
        ),
        "Confirm the expected hostname with the asset owner and configuration management, then "
        "align the runtime hostname and /etc/hostname if the difference is not expected.",
        (),
        Confidence.HIGH,
    ),
    _rule(
        "SYS_SUSPICIOUS_KERNEL_CMDLINE",
        "Kernel command line contains rescue or single-user boot options",
        "system",
        Severity.MEDIUM,
        "The running kernel was booted with options such as init=/bin/sh, single, rd.break or "
        "systemd.unit=rescue.target. These bypass normal service startup and authentication "
        "controls, which is useful for offline tampering and for hiding a compromised boot.",
        (
            "Emergency maintenance or password recovery performed by an administrator.",
            "Some hardened or appliance images use custom init parameters.",
        ),
        "Confirm the boot parameters with the bootloader configuration and change records. If "
        "unexplained, treat the host as potentially tampered with, review bootloader and kernel "
        "integrity, and rebuild from trusted media.",
        ("T1495",),
        Confidence.MEDIUM,
    ),
    # ---------------------------------------------------------------- process
    _rule(
        "PROC_EXEC_FROM_TMP",
        "Process executing from a temporary directory",
        "process",
        Severity.HIGH,
        "A process executable resides in /tmp, /var/tmp or a similar world-writable temporary "
        "location. Legitimate daemons and packages install to /usr, /opt or /srv; running from "
        "a temporary directory is a common way to execute an uploaded payload without touching "
        "persistent system paths.",
        (
            "User-compiled tools, installers and some backup or forensic utilities run from /tmp.",
            "Package builds and CI jobs frequently stage binaries in temporary directories.",
            "Java or Python applications may unpack helper binaries into /tmp.",
        ),
        "Identify the binary's origin and hash it before removal. If it is not attributable to a "
        "known administrative action, isolate the host, preserve the file, and review the "
        "process tree and network activity for lateral movement.",
        ("T1059", "T1036"),
        Confidence.MEDIUM,
    ),
    _rule(
        "PROC_EXEC_FROM_DEV_SHM",
        "Process executing from /dev/shm",
        "process",
        Severity.CRITICAL,
        "The executable is stored in /dev/shm, a shared-memory filesystem that is writable, "
        "memory-backed and commonly overlooked by disk-focused monitoring. Malware and "
        "fileless-style loaders frequently stage payloads there.",
        (
            "A small number of legitimate applications use /dev/shm for shared objects.",
            "Some container runtimes place helper executables in shared memory.",
        ),
        "Hash and preserve the executable, inspect the parent process and deletion timing, and "
        "treat execution from /dev/shm as malicious until provenance is proven.",
        ("T1059", "T1036"),
        Confidence.MEDIUM,
    ),
    _rule(
        "PROC_EXEC_FROM_HOME",
        "Process executing from a user home directory",
        "process",
        Severity.MEDIUM,
        "A process executable is located under /home. User-writable directories are attractive "
        "for dropped payloads because users and some backup tools have write access there.",
        (
            "User-installed tools such as language runtimes, Steam, VS Code servers or "
            "user-local package managers legitimately live in home directories.",
            "Remote-development and CI agents often run from a home directory.",
        ),
        "Verify the owning user and installation method. If the binary is not part of a known "
        "user toolchain, preserve it and review the account's login and file history.",
        ("T1036",),
        Confidence.LOW,
    ),
    _rule(
        "PROC_DELETED_EXECUTABLE",
        "Process is running a deleted executable",
        "process",
        Severity.HIGH,
        "The executable backing a running process has been unlinked from the filesystem. This is "
        "a classic technique for running a payload and then removing it from disk while it stays "
        "resident in memory, defeating simple file-based scanning.",
        (
            "Package upgrades legitimately replace binaries while old processes keep running.",
            "Long-running services may survive a package update until the next restart.",
        ),
        "Compare the process start time with package-manager history. If the process predates no "
        "known upgrade, preserve /proc/<pid>/exe, capture memory if authorised, and review "
        "child processes and network connections.",
        ("T1036", "T1070.004"),
        Confidence.MEDIUM,
    ),
    _rule(
        "PROC_ROOT_FROM_SUSPICIOUS_PATH",
        "Root process executing from a writable or unusual path",
        "process",
        Severity.CRITICAL,
        "A process running as UID 0 has its executable in a temporary, shared-memory or user "
        "home directory. This combines maximum privilege with a path that non-root users can "
        "write to, which is a strong privilege-escalation or implant indicator.",
        (
            "An administrator may have launched a root shell or tool from a staging directory.",
            "Some appliance and container entrypoints intentionally run from /home or /tmp.",
        ),
        "Treat as a potential active compromise: preserve the executable and process context, "
        "review how the process was launched (parent, terminal, service), and rotate credentials "
        "used on the host.",
        ("T1068", "T1036"),
        Confidence.MEDIUM,
    ),
    _rule(
        "PROC_SUSPICIOUS_CMDLINE",
        "Process command line matches a known attack pattern",
        "process",
        Severity.HIGH,
        "The command line contains patterns frequently used for reverse shells, download-and-"
        "execute chains, encoded payloads or log tampering. The matched pattern is recorded in "
        "the finding details so it can be reviewed in context.",
        (
            "Administrators legitimately use curl/wget pipelines, base64 and netcat for "
            "troubleshooting and automation.",
            "Build systems and deployment scripts often contain these constructs.",
            "Security tooling itself may use encoded command lines.",
        ),
        "Review the full command line, parent process, user and timing. Confirm whether the "
        "activity matches an approved administrative task; otherwise isolate and investigate.",
        ("T1059", "T1071"),
        Confidence.MEDIUM,
    ),
    _rule(
        "PROC_HIDDEN_NAME",
        "Process name is disguised or hidden",
        "process",
        Severity.MEDIUM,
        "The process name begins with a dot or whitespace, or consists only of punctuation. "
        "This can hide the process from casual `ps` output and from operators who sort by name, "
        "and is uncommon for legitimate daemons.",
        (
            "Some legitimate processes use dotted names for versioned helpers.",
            "Thread names and kernel workers can have unusual formatting.",
        ),
        "Inspect the executable path, parent process and start time. If the name does not match a "
        "known package, preserve the binary and investigate its network activity.",
        ("T1036.004",),
        Confidence.LOW,
    ),
    _rule(
        "PROC_NO_EXECUTABLE",
        "Process has no readable executable path",
        "process",
        Severity.LOW,
        "psutil could not resolve an executable path for a running process. This is expected for "
        "kernel threads and for processes owned by other users when running unprivileged, but it "
        "can also indicate a process that hides its backing file.",
        (
            "Kernel threads have no user-space executable.",
            "Running without root hides other users' process details on some kernels.",
            "Short-lived processes can disappear between enumeration and inspection.",
        ),
        "Re-run the collection as root if permitted, and inspect /proc/<pid>/exe and "
        "/proc/<pid>/maps directly for the affected PID.",
        (),
        Confidence.LOW,
    ),
    # ---------------------------------------------------------------- network
    _rule(
        "NET_SUSPICIOUS_LISTENER",
        "Listening socket owned by a suspicious process",
        "network",
        Severity.HIGH,
        "A process is listening for inbound connections while its executable resides in a "
        "temporary, shared-memory or user-writable path, or the executable has been deleted. "
        "Legitimate network services are normally installed in system paths and are owned by "
        "package-managed accounts.",
        (
            "Development servers started by users from their home directory.",
            "Container entrypoints and language runtimes may listen from unusual paths.",
            "A service restarted during a package upgrade may briefly show a deleted binary.",
        ),
        "Correlate the listening port with the expected service inventory, preserve the binary, "
        "and review inbound connections to that port. Block the port at the host firewall only "
        "after preserving evidence.",
        ("T1105", "T1071"),
        Confidence.MEDIUM,
    ),
    _rule(
        "NET_SUSPICIOUS_CONNECTION",
        "Established connection from a suspicious process",
        "network",
        Severity.HIGH,
        "An established connection is associated with a process whose executable is in a "
        "temporary or user-writable path, or has been deleted. This is consistent with command-"
        "and-control or data exfiltration from a staged payload.",
        (
            "Legitimate user applications and development tools connect out from home directories.",
            "Package updates and telemetry can originate from unexpected processes.",
        ),
        "Preserve connection metadata and the executable, review the remote endpoint reputation "
        "using local threat intelligence (no automatic upload), and isolate the host if the "
        "connection is not attributable.",
        ("T1071", "T1041"),
        Confidence.MEDIUM,
    ),
    _rule(
        "NET_PUBLIC_LISTENER",
        "Service listening on all interfaces",
        "network",
        Severity.INFO,
        "A listening socket is bound to 0.0.0.0 or ::, meaning it accepts connections on every "
        "interface. This is an exposure observation rather than a compromise indicator, and is "
        "recorded so the listening-service inventory can be reviewed.",
        (
            "Web servers, SSH and many legitimate services intentionally bind to all interfaces.",
            "Container port publishing commonly results in wildcard listeners.",
        ),
        "Confirm every wildcard listener is required and protected by host and network firewalls. "
        "Bind services to a specific management interface where possible.",
        (),
        Confidence.HIGH,
    ),
    _rule(
        "NET_UNATTRIBUTED_LISTENER",
        "Listening socket could not be attributed to a process",
        "network",
        Severity.LOW,
        "A listening socket was found in /proc/net but no owning process could be identified. "
        "When running as root this is unexpected and may indicate a process that is hiding or a "
        "socket held in a different namespace.",
        (
            "Sockets can belong to another network namespace or container.",
            "Kernel sockets (for example NFS or sunrpc) have no user-space process.",
            "Unprivileged collection cannot attribute other users' sockets.",
        ),
        "Re-collect as root and inspect `ss -lntup` output, including other network namespaces, "
        "to attribute the socket.",
        (),
        Confidence.LOW,
    ),
    # ------------------------------------------------------------------ users
    _rule(
        "USER_UID0_NONROOT",
        "Additional UID 0 account detected",
        "user",
        Severity.CRITICAL,
        "An account other than root has UID 0 in /etc/passwd. Any UID 0 account has full "
        "administrative privilege regardless of its name, and extra root-equivalent accounts are "
        "a common backdoor persistence mechanism.",
        (
            "Some hardened images intentionally provide a second emergency root account.",
            "Configuration-management or appliance software may create a documented UID 0 alias.",
        ),
        "Validate the account against the asset owner and change records. If unauthorized, "
        "preserve /etc/passwd, /etc/shadow and authentication logs, disable the account through "
        "the approved change process, and rotate root credentials.",
        ("T1136.001", "T1078.003"),
        Confidence.HIGH,
    ),
    _rule(
        "USER_RECENT_UID0_ACCOUNT",
        "Recently created UID 0 account",
        "user",
        Severity.CRITICAL,
        "A UID 0 account appears in the current /etc/passwd but not in the distribution's "
        "backup /etc/passwd-, or its home directory was created recently. Combining root "
        "privilege with recent creation is a strong indicator of an attacker-created backdoor.",
        (
            "A documented administrative change may have created a root-equivalent account.",
            "Image build pipelines can produce passwd files without a matching backup.",
        ),
        "Treat as an active backdoor until proven otherwise: preserve account databases and "
        "logs, review sudo and SSH keys for the account, and remove it only through an approved "
        "incident process.",
        ("T1136.001",),
        Confidence.MEDIUM,
    ),
    _rule(
        "USER_RECENT_ACCOUNT",
        "Account appears to have been created recently",
        "user",
        Severity.MEDIUM,
        "An account is present in /etc/passwd but absent from the distribution's previous "
        "account database /etc/passwd-. This is a reliable signal that the account was added "
        "since the backup was written, although the exact time cannot be established from the "
        "file alone. New accounts are a common persistence mechanism.",
        (
            "A documented administrative or provisioning change may have added the account.",
            "Image build pipelines can produce a passwd file without a matching backup.",
            "The backup may be stale or absent on some distributions, in which case no "
            "comparison is made.",
        ),
        "Confirm the account against the identity-management record and change history. Review "
        "its sudo rights, SSH keys and recent logins before deciding whether it is authorised.",
        ("T1136.001",),
        Confidence.MEDIUM,
    ),
    _rule(
        "USER_EMPTY_PASSWORD",
        "Account with an empty password field",
        "user",
        Severity.CRITICAL,
        "An entry in /etc/shadow has an empty password field, allowing authentication without a "
        "password from any console or service that permits password login.",
        (
            "Some appliance or recovery accounts are intentionally passwordless but restricted "
            "to a local console.",
            "A misconfigured provisioning script may leave the field empty.",
        ),
        "Set a strong password or lock the account immediately through the approved change "
        "process, then review authentication logs for use of the account.",
        ("T1078.003",),
        Confidence.HIGH,
    ),
    _rule(
        "USER_SUDO_NOPASSWD",
        "Sudo rule grants passwordless privilege",
        "user",
        Severity.HIGH,
        "A sudoers entry contains NOPASSWD for a non-root principal. Passwordless sudo turns "
        "compromise of that account into immediate root access without an additional "
        "authentication factor.",
        (
            "Automation accounts, backup jobs and monitoring agents often require NOPASSWD.",
            "Some desktop environments grant limited NOPASSWD commands for convenience.",
        ),
        "Confirm each NOPASSWD rule against the automation inventory, restrict it to the "
        "specific commands required, and remove broad NOPASSWD grants that are not documented.",
        ("T1548.003",),
        Confidence.MEDIUM,
    ),
    _rule(
        "USER_SUDO_GROUP_MEMBER",
        "Account is a member of a sudo-capable group",
        "user",
        Severity.INFO,
        "An account belongs to sudo, wheel or admin. Membership is recorded for inventory and "
        "correlation; it is not inherently malicious.",
        (
            "Administrators and automation accounts are expected members.",
            "Cloud images frequently grant the default user sudo access.",
        ),
        "Review membership quarterly and remove stale accounts. Ensure each member has MFA or a "
        "strong password and that sudo activity is logged centrally.",
        (),
        Confidence.HIGH,
    ),
    _rule(
        "USER_SYSTEM_ACCOUNT_INTERACTIVE",
        "System account has an interactive login shell",
        "user",
        Severity.LOW,
        "A service account with UID below 1000 has a shell such as /bin/bash instead of "
        "/usr/sbin/nologin or /bin/false. This allows interactive login if a password or key is "
        "ever set, contrary to least privilege.",
        (
            "Some distributions create system accounts with /bin/sh for maintenance scripts.",
            "Legacy service accounts may predate modern nologin conventions.",
        ),
        "Confirm the account does not need interactive access and change the shell to "
        "/usr/sbin/nologin through configuration management.",
        ("T1078.003",),
        Confidence.MEDIUM,
    ),
    _rule(
        "USER_DUPLICATE_UID",
        "Duplicate UID assigned to multiple accounts",
        "user",
        Severity.MEDIUM,
        "Two or more account names share a UID. File ownership and audit logs become ambiguous, "
        "and an attacker can use an alias account to retain access after the original account is "
        "disabled.",
        (
            "Legacy migrations sometimes intentionally alias accounts.",
            "Container images may duplicate UIDs for compatibility.",
        ),
        "Determine which account is authoritative, preserve the account databases, and remove or "
        "re-UID the alias through change management.",
        ("T1136.001",),
        Confidence.HIGH,
    ),
    _rule(
        "USER_HOME_RECENT",
        "User home directory was created recently",
        "user",
        Severity.LOW,
        "A home directory under /home has a recent creation/change time. This is a weak "
        "indicator of a newly added account; inode change time can be updated by legitimate "
        "file operations.",
        (
            "Files restored from backup or migrated between hosts update ctime.",
            "Package installation and dotfile synchronisation touch home directories.",
        ),
        "Correlate with /etc/passwd changes and authentication logs before drawing conclusions.",
        ("T1136.001",),
        Confidence.LOW,
    ),
    # -------------------------------------------------------------------- ssh
    _rule(
        "SSH_PERMIT_EMPTY_PASSWORDS",
        "sshd permits empty passwords",
        "ssh",
        Severity.CRITICAL,
        "The effective sshd configuration enables PermitEmptyPasswords. Combined with an account "
        "that has no password, this allows unauthenticated remote login.",
        (
            "A deliberately isolated lab environment may enable this temporarily.",
        ),
        "Set PermitEmptyPasswords to no, reload sshd through the approved change process, and "
        "audit accounts for empty password fields.",
        ("T1078.003", "T1110"),
        Confidence.HIGH,
    ),
    _rule(
        "SSH_ROOT_LOGIN_ENABLED",
        "sshd permits direct root login",
        "ssh",
        Severity.MEDIUM,
        "The effective PermitRootLogin setting allows root to authenticate over SSH. Direct root "
        "login removes accountability and gives brute-force attempts a high-value target.",
        (
            "Some legacy automation or appliance management requires root SSH.",
            "Key-only root login may be an accepted organisational standard.",
        ),
        "Prefer PermitRootLogin prohibit-password or no, require administrators to use named "
        "accounts with sudo, and monitor root SSH attempts.",
        ("T1078.003", "T1110.001"),
        Confidence.HIGH,
    ),
    _rule(
        "SSH_PASSWORD_AUTH_ENABLED",
        "sshd permits password authentication",
        "ssh",
        Severity.LOW,
        "PasswordAuthentication is enabled. Password-based SSH is exposed to credential "
        "stuffing and brute force, whereas key-based authentication is more resistant.",
        (
            "Environments without a key-distribution process often rely on passwords.",
            "Some jump hosts intentionally support password plus MFA.",
        ),
        "Move to key-based authentication with MFA where possible, or enforce strong password "
        "policy, rate limiting and fail2ban-style controls.",
        ("T1110.001",),
        Confidence.HIGH,
    ),
    _rule(
        "SSH_WEAK_MAX_AUTH_TRIES",
        "sshd allows an excessive number of authentication attempts",
        "ssh",
        Severity.LOW,
        "MaxAuthTries is above the common hardening baseline of 3-6. A higher value gives "
        "automated credential guessing more attempts per connection.",
        (
            "Some environments raise the limit to accommodate multi-key agents or legacy clients.",
        ),
        "Reduce MaxAuthTries to 3-6 and enforce connection rate limiting at the firewall or with "
        "sshd's own limits.",
        ("T1110.001",),
        Confidence.HIGH,
    ),
    _rule(
        "SSH_FAILED_LOGIN_BURST",
        "Repeated SSH authentication failures",
        "ssh",
        Severity.MEDIUM,
        "Authentication logs show a high number of failed SSH logins, either from a single "
        "source address or in aggregate. This is consistent with password guessing or credential "
        "stuffing.",
        (
            "Internet-exposed SSH commonly receives background scanning and failed logins.",
            "A user with a stale key or password can generate repeated failures.",
            "Monitoring or vulnerability scanners may probe SSH authentication.",
        ),
        "Confirm the source addresses against known scanners and administrative networks, "
        "enforce key-only authentication, and add rate limiting. Do not block addresses before "
        "preserving logs.",
        ("T1110.001",),
        Confidence.MEDIUM,
    ),
    _rule(
        "SSH_SUCCESS_AFTER_FAILURES",
        "Successful SSH login after repeated failures from the same source",
        "ssh",
        Severity.HIGH,
        "A source address that produced multiple failed SSH logins later authenticated "
        "successfully. This is the signature of a successful brute-force or credential-stuffing "
        "attack and warrants immediate validation with the account owner.",
        (
            "A legitimate user may mistype a password several times before succeeding.",
            "An automated deployment may retry with stale credentials and then succeed.",
            "NAT or a shared proxy can make unrelated users appear as one source address.",
        ),
        "Contact the account owner, review the session's commands and source geography, preserve "
        "auth logs, and rotate the account's credentials and keys if the login is not confirmed.",
        ("T1110.001", "T1078"),
        Confidence.MEDIUM,
    ),
    _rule(
        "SSH_ROOT_LOGIN_SUCCESS",
        "Successful direct root SSH login",
        "ssh",
        Severity.MEDIUM,
        "Authentication logs record a successful SSH login as root. Even where permitted, direct "
        "root sessions bypass per-administrator accountability and deserve verification.",
        (
            "Documented emergency or automation access may use root SSH.",
            "Some appliance management workflows require root login.",
        ),
        "Confirm the session with the operator, prefer named accounts with sudo, and review the "
        "session's commands and source address.",
        ("T1078.003",),
        Confidence.MEDIUM,
    ),
    _rule(
        "SSH_AUTHORIZED_KEY_RECENT",
        "SSH authorized_keys file was modified recently",
        "ssh",
        Severity.MEDIUM,
        "An authorized_keys file has a recent modification time. Adding a key is a common and "
        "quiet persistence technique because it survives password resets.",
        (
            "Administrators legitimately rotate or add keys during onboarding.",
            "Configuration management may rewrite key files periodically.",
        ),
        "Compare the key fingerprints with the approved key inventory, remove unknown keys "
        "through change management, and review authentication logs for their use.",
        ("T1098.004",),
        Confidence.MEDIUM,
    ),
    _rule(
        "SSH_AUTHORIZED_KEY_ROOT",
        "Root account has authorized SSH keys",
        "ssh",
        Severity.INFO,
        "One or more public keys are authorized for root. This is an inventory observation, not "
        "evidence of compromise, but root keys are high-value persistence.",
        (
            "Automation, backup and configuration-management systems commonly use root keys.",
            "Break-glass access may be implemented with a root key.",
        ),
        "Verify each fingerprint against the key inventory, prefer dedicated automation accounts, "
        "and consider restricting root keys with from= or command= options.",
        ("T1098.004",),
        Confidence.HIGH,
    ),
    _rule(
        "SSH_AUTHORIZED_KEY_FORCED_COMMAND",
        "SSH key forces execution of a suspicious command",
        "ssh",
        Severity.HIGH,
        "An authorized_keys entry uses the command= option to run a command containing "
        "download-and-execute, encoded payload or shell patterns. Forced commands are legitimate "
        "for backups, but this content is consistent with a backdoor key.",
        (
            "Backup and deployment keys legitimately use command= wrappers.",
            "Restricted shell wrappers may include pipes and redirection.",
        ),
        "Compare the key fingerprint and forced command with the automation inventory, preserve "
        "the file, and remove unauthorized keys through the approved process.",
        ("T1098.004",),
        Confidence.MEDIUM,
    ),
    _rule(
        "SSH_AUTHORIZED_KEY_WORLD_WRITABLE",
        "SSH authorized_keys file is writable by other users",
        "ssh",
        Severity.HIGH,
        "An authorized_keys file has world-writable permissions. Any local user could add a key "
        "and obtain the owner's SSH access, including root's.",
        (
            "A misconfigured deployment script may have created loose permissions.",
        ),
        "Restrict the file to 0600 and its .ssh directory to 0700, then audit the current key "
        "contents for unauthorized entries.",
        ("T1222.002", "T1098.004"),
        Confidence.HIGH,
    ),
    _rule(
        "SSH_PRIVATE_KEY_EXPOSED",
        "SSH private key is readable by other users",
        "ssh",
        Severity.HIGH,
        "A private key file under a .ssh directory has group- or world-readable permissions. "
        "Any local user or compromised service account could copy the key and impersonate the "
        "owner.",
        (
            "Some backup or container tooling copies keys with permissive modes by mistake.",
        ),
        "Restrict private keys to 0600, rotate any key that was exposed, and review "
        "authentication logs for its use.",
        ("T1552.004",),
        Confidence.HIGH,
    ),
    # ------------------------------------------------------------- persistence
    _rule(
        "PERS_LD_PRELOAD",
        "Global dynamic-linker preload file is present",
        "persistence",
        Severity.HIGH,
        "/etc/ld.so.preload forces a shared library into almost every dynamically linked process. "
        "It is a powerful userland rootkit and persistence mechanism and is absent on most "
        "standard distributions.",
        (
            "Some endpoint-security and licensing products legitimately use ld.so.preload.",
            "An administrator may have added a profiling or instrumentation library.",
        ),
        "Identify the referenced library and its package provenance. If unexplained, preserve "
        "the file and library, compare against the package manifest, and rebuild the host from "
        "trusted media.",
        ("T1574.006",),
        Confidence.HIGH,
    ),
    _rule(
        "PERS_LD_SO_CONF_SUSPICIOUS",
        "Dynamic-linker configuration references a writable path",
        "persistence",
        Severity.HIGH,
        "An ld.so.conf or ld.so.conf.d entry points to a temporary or user-writable directory. "
        "Adding such a path lets an unprivileged user influence library resolution for setuid or "
        "privileged programs.",
        (
            "Custom application deployments may add /opt or /usr/local paths, which are normally "
            "root-owned and therefore not flagged.",
        ),
        "Remove writable paths from the linker configuration and review the directory contents "
        "for planted libraries.",
        ("T1574.006",),
        Confidence.MEDIUM,
    ),
    _rule(
        "PERS_CRON_SUSPICIOUS",
        "Cron entry contains a suspicious command",
        "persistence",
        Severity.HIGH,
        "A cron job contains download-and-execute, encoded payload, reverse-shell or log-"
        "tampering patterns. Cron is a durable and frequently overlooked persistence location.",
        (
            "Legitimate maintenance jobs commonly use curl, wget and shell pipelines.",
            "Configuration-management agents may install encoded or obfuscated commands.",
        ),
        "Compare the job with the configuration-management source of truth, preserve the cron "
        "file, and remove unauthorized entries through change management.",
        ("T1053.003",),
        Confidence.MEDIUM,
    ),
    _rule(
        "PERS_CRON_RECENT",
        "Cron file was modified recently",
        "persistence",
        Severity.MEDIUM,
        "A cron file has a recent modification time. New or changed scheduled jobs are a common "
        "persistence mechanism and should be attributable to an approved change.",
        (
            "Package updates and configuration management routinely rewrite cron files.",
            "Administrators may add jobs during incident response or maintenance.",
        ),
        "Diff the job against the previous configuration and confirm the change with the system "
        "owner.",
        ("T1053.003",),
        Confidence.MEDIUM,
    ),
    _rule(
        "PERS_SYSTEMD_SUSPICIOUS_EXEC",
        "Systemd unit executes a suspicious command or path",
        "persistence",
        Severity.HIGH,
        "A systemd unit's ExecStart points to a temporary or user-writable path, or contains "
        "download-and-execute or encoded-command patterns. Systemd services start automatically "
        "and blend into normal service management.",
        (
            "Custom applications and containers sometimes run from /opt or /home by design.",
            "Legitimate units may use shell wrappers with pipes.",
        ),
        "Compare the unit with the package manifest and configuration management, preserve the "
        "unit and executable, and disable unauthorized services through change management.",
        ("T1543.002",),
        Confidence.MEDIUM,
    ),
    _rule(
        "PERS_SYSTEMD_RECENT",
        "Systemd unit was created or modified recently",
        "persistence",
        Severity.MEDIUM,
        "A unit file under /etc/systemd/system has a recent modification time. Units placed in "
        "/etc override vendor units and are a common persistence location.",
        (
            "Administrators and package upgrades legitimately modify units.",
            "Configuration management may rewrite drop-ins on a schedule.",
        ),
        "Review the unit's provenance and diff it against the vendor version in /usr/lib. Confirm "
        "unexpected changes with the system owner.",
        ("T1543.002",),
        Confidence.MEDIUM,
    ),
    _rule(
        "PERS_RC_LOCAL_SUSPICIOUS",
        "rc.local contains a suspicious command",
        "persistence",
        Severity.HIGH,
        "The legacy /etc/rc.local startup script contains download-and-execute or encoded-command "
        "patterns. rc.local runs at boot and is often overlooked on systemd hosts.",
        (
            "Legacy custom boot tasks may legitimately use network downloads.",
            "Some hardware vendors install rc.local hooks.",
        ),
        "Review the script against the system build documentation, preserve it, and remove "
        "unexpected commands through change management.",
        ("T1037.004",),
        Confidence.MEDIUM,
    ),
    _rule(
        "PERS_PROFILE_SUSPICIOUS",
        "Shell profile contains a suspicious command",
        "persistence",
        Severity.HIGH,
        "A system-wide or user shell profile contains download-and-execute, encoded-payload or "
        "reverse-shell patterns. Profile scripts execute on login and can re-establish access "
        "for every interactive session.",
        (
            "Some environments use profile scripts for legitimate agent bootstrap or telemetry.",
            "Administrators may add environment setup with command substitutions.",
        ),
        "Diff the profile against the package version, preserve it, and remove unauthorized "
        "lines through change management.",
        ("T1546.004",),
        Confidence.MEDIUM,
    ),
    _rule(
        "PERS_SSH_RC_SUSPICIOUS",
        "SSH rc script contains a suspicious command",
        "persistence",
        Severity.HIGH,
        "An SSH rc script (/etc/ssh/sshrc or ~/.ssh/rc) contains download-and-execute or encoded-"
        "command patterns. These scripts run on every SSH login and are rarely used legitimately.",
        (
            "Some jump-host environments use sshrc for session logging or environment setup.",
        ),
        "Compare the script with the approved SSH configuration, preserve it, and remove "
        "unexpected commands.",
        ("T1546",),
        Confidence.MEDIUM,
    ),
    _rule(
        "PERS_AT_JOB",
        "Scheduled at job is present",
        "persistence",
        Severity.MEDIUM,
        "A job exists in the at spool. `at` jobs are one-shot scheduled commands that are easy to "
        "overlook and can be used to trigger a payload after a delay.",
        (
            "Administrators use at for legitimate one-off maintenance.",
            "Batch processing systems may schedule at jobs.",
        ),
        "Inspect the job command and owner, correlate with change records, and remove "
        "unauthorized jobs through change management.",
        ("T1053.002",),
        Confidence.MEDIUM,
    ),
    _rule(
        "PERS_INITD_RECENT",
        "Init script was modified recently",
        "persistence",
        Severity.MEDIUM,
        "A script in /etc/init.d has a recent modification time. Init scripts can still run on "
        "systemd hosts through compatibility units and are a persistence location.",
        (
            "Package upgrades and legacy service maintenance modify init scripts.",
        ),
        "Diff the script against the vendor package and confirm the change with the system owner.",
        ("T1543.002",),
        Confidence.MEDIUM,
    ),
    _rule(
        "PERS_INITD_SUSPICIOUS",
        "Init script contains a suspicious command",
        "persistence",
        Severity.HIGH,
        "A script in /etc/init.d contains download-and-execute, encoded-payload or reverse-shell "
        "patterns. Legacy init scripts can still execute on systemd hosts through compatibility "
        "units and are frequently overlooked.",
        (
            "Legacy service scripts may legitimately download updates or use shell pipelines.",
            "Vendor installers sometimes place complex shell logic in init scripts.",
        ),
        "Compare the script with the vendor package and configuration management, preserve it, "
        "and remove unauthorized commands through change management.",
        ("T1543.002",),
        Confidence.MEDIUM,
    ),
    _rule(
        "PERS_USER_SYSTEMD_UNIT",
        "Per-user systemd unit is present",
        "persistence",
        Severity.INFO,
        "A systemd user unit exists under a home directory. User units provide persistence "
        "without root and are frequently missed by system-wide reviews.",
        (
            "Desktop applications, containers and user services legitimately use user units.",
        ),
        "Review the unit's ExecStart and enablement for the affected user, and confirm it is "
        "expected.",
        ("T1543.002",),
        Confidence.HIGH,
    ),
    # ------------------------------------------------------------- filesystem
    _rule(
        "FS_SUID_IN_WRITABLE_DIR",
        "SUID/SGID binary in a writable directory",
        "filesystem",
        Severity.HIGH,
        "A SUID or SGID executable resides in a temporary, home or variable directory. If an "
        "unprivileged user can replace the file, they can execute arbitrary code with the file "
        "owner's privileges.",
        (
            "Some vendor applications install SUID helpers in /opt or /var.",
            "User-mounted filesystems can legitimately contain SUID tools.",
        ),
        "Preserve the binary and its metadata, verify its package ownership with the package "
        "manager, and remove the SUID bit through change management if unauthorized.",
        ("T1548.001",),
        Confidence.HIGH,
    ),
    _rule(
        "FS_SUID_UNEXPECTED",
        "SUID/SGID binary outside standard system directories",
        "filesystem",
        Severity.MEDIUM,
        "A SUID or SGID executable was found outside the standard package-managed binary "
        "directories. This is an inventory observation that becomes significant when combined "
        "with unusual ownership or modification time.",
        (
            "Third-party software frequently installs SUID helpers in /opt or /usr/local.",
            "Container images may place binaries in non-standard paths.",
        ),
        "Compare the binary against the package manifest and approved application inventory, and "
        "remove unnecessary SUID bits.",
        ("T1548.001",),
        Confidence.MEDIUM,
    ),
    _rule(
        "FS_EXEC_IN_TMP",
        "Executable file in a temporary directory",
        "filesystem",
        Severity.MEDIUM,
        "A regular file with execute permission exists in /tmp, /var/tmp or /dev/shm. Temporary "
        "directories are writable by unprivileged users and are commonly used to stage payloads.",
        (
            "Installers, build jobs and user tools legitimately place executables in /tmp.",
            "Package managers may stage helper scripts there.",
        ),
        "Hash the file, identify its owner and creation time, and correlate with process and "
        "network activity. Preserve it before cleanup.",
        ("T1059", "T1036"),
        Confidence.MEDIUM,
    ),
    _rule(
        "FS_HIDDEN_EXEC_IN_TMP",
        "Hidden executable in a temporary directory",
        "filesystem",
        Severity.HIGH,
        "An executable file in a temporary directory has a name beginning with a dot or "
        "whitespace, hiding it from default directory listings. This combination is strongly "
        "associated with staged payloads.",
        (
            "Some legitimate tools create hidden helper scripts in temporary directories.",
        ),
        "Preserve and hash the file, inspect its content and creation process, and treat it as "
        "malicious unless provenance is established.",
        ("T1036.005", "T1564.001"),
        Confidence.MEDIUM,
    ),
    _rule(
        "FS_WORLD_WRITABLE_SENSITIVE",
        "Security-sensitive file is world-writable",
        "filesystem",
        Severity.HIGH,
        "A file that controls authentication, privilege or startup behaviour is writable by any "
        "local user. This permits direct privilege escalation or persistence.",
        (
            "A provisioning mistake or umask error may have produced loose permissions.",
            "Some container build layers preserve unusual modes.",
        ),
        "Restore restrictive ownership and permissions (for example root:root 0644 or 0600), "
        "then review the file's content for unauthorized changes.",
        ("T1222.002",),
        Confidence.HIGH,
    ),
    _rule(
        "FS_WORLD_WRITABLE_ETC_DIR",
        "Non-sticky world-writable directory in /etc",
        "filesystem",
        Severity.HIGH,
        "A directory under /etc is world-writable without the sticky bit. Any local user could "
        "create or replace configuration files, enabling persistence or privilege escalation.",
        (
            "Some application-specific configuration directories are intentionally shared.",
        ),
        "Remove world-write permission and review the directory for files created by "
        "unprivileged users.",
        ("T1222.002",),
        Confidence.HIGH,
    ),
    _rule(
        "FS_RECENT_SECURITY_CONFIG_CHANGE",
        "Security-sensitive configuration changed recently",
        "filesystem",
        Severity.MEDIUM,
        "A security-relevant file (account database, sudoers, SSH configuration, cron, systemd "
        "unit or linker configuration) has a recent modification time. Recent changes should be "
        "attributable to an approved administrative action.",
        (
            "Package upgrades and configuration management routinely touch these files.",
            "The incident response process itself may have changed them.",
        ),
        "Diff the file against the package or configuration-management baseline and confirm the "
        "change with the system owner.",
        ("T1222",),
        Confidence.MEDIUM,
    ),
    _rule(
        "FS_DEV_SHM_EXEC",
        "Executable file in /dev/shm",
        "filesystem",
        Severity.HIGH,
        "An executable file exists in /dev/shm. The shared-memory filesystem is writable and "
        "memory-backed, making it a preferred staging area for fileless and memory-resident "
        "malware.",
        (
            "A small number of legitimate applications use executable shared-memory objects.",
        ),
        "Preserve and hash the file, identify the creating process, and review process and "
        "network activity for the same time window.",
        ("T1059", "T1036"),
        Confidence.MEDIUM,
    ),
    # ------------------------------------------------------------------- logs
    _rule(
        "LOG_AUTH_FAILURE_BURST",
        "High volume of authentication failures",
        "logs",
        Severity.MEDIUM,
        "Authentication logs contain a high number of failed logins across SSH, sudo or local "
        "authentication. This may indicate brute force, credential stuffing or a misconfigured "
        "service account.",
        (
            "Internet-exposed services receive constant background scanning.",
            "A stale credential in an automation job can generate repeated failures.",
            "Log rotation may duplicate entries and inflate counts.",
        ),
        "Validate the source addresses and target accounts, enforce rate limiting and key-based "
        "authentication, and preserve logs before any blocking action.",
        ("T1110",),
        Confidence.MEDIUM,
    ),
    _rule(
        "LOG_ROOT_LOGIN",
        "Root login recorded in authentication logs",
        "logs",
        Severity.MEDIUM,
        "Authentication logs record a successful login for root, either locally or remotely. "
        "Direct root sessions reduce accountability and are worth validating even when permitted.",
        (
            "Emergency maintenance or documented automation may use root.",
            "Console access during recovery commonly uses root.",
        ),
        "Confirm the session with the operator and prefer named accounts with sudo for routine "
        "administration.",
        ("T1078.003",),
        Confidence.MEDIUM,
    ),
    _rule(
        "LOG_SUDO_SUSPICIOUS_COMMAND",
        "Sudo command matches a suspicious pattern",
        "logs",
        Severity.HIGH,
        "A command executed through sudo contains download-and-execute, encoded-payload, "
        "reverse-shell or log-tampering patterns. Sudo logs provide strong attribution because "
        "they include the invoking user and terminal.",
        (
            "Administrators legitimately use these commands for troubleshooting.",
            "Automation may run encoded or piped commands through sudo.",
        ),
        "Review the full sudo log entry, confirm the operator's intent, and preserve the command "
        "and any resulting artefacts.",
        ("T1548.003", "T1059"),
        Confidence.MEDIUM,
    ),
    _rule(
        "LOG_ACCOUNT_CREATED",
        "Account or group management activity recorded",
        "logs",
        Severity.MEDIUM,
        "Logs record useradd, usermod, userdel, groupadd, passwd or similar account-management "
        "commands. Account changes are a common persistence mechanism and should match approved "
        "changes.",
        (
            "Provisioning automation and package installation legitimately create accounts.",
            "Administrators may add service accounts during maintenance.",
        ),
        "Compare the change with the identity-management record and review the new account's "
        "privileges, keys and recent logins.",
        ("T1136",),
        Confidence.MEDIUM,
    ),
    _rule(
        "LOG_AUTH_LOG_EMPTY",
        "Authentication log is present but empty",
        "logs",
        Severity.MEDIUM,
        "An authentication log file exists with zero bytes. Log tampering often truncates or "
        "replaces auth logs to remove evidence of access.",
        (
            "A freshly rotated log can be empty.",
            "Logging may be misconfigured or the service may not have started yet.",
        ),
        "Compare with journald and remote log aggregation, check file metadata and rotation "
        "history, and treat unexplained truncation as potential anti-forensics.",
        ("T1070.002",),
        Confidence.LOW,
    ),
    # -------------------------------------------------------------------- ioc
    _rule(
        "IOC_MATCH",
        "Collected evidence matches a supplied indicator",
        "ioc",
        Severity.HIGH,
        "An IP address, domain, file hash, path or other indicator supplied by the analyst was "
        "found in collected evidence. A match is a correlation, not proof of compromise: it must "
        "be validated against the indicator's provenance and the surrounding context.",
        (
            "Shared infrastructure, CDNs and cloud providers can make an IP indicator ambiguous.",
            "A domain may appear in documentation, package metadata or benign telemetry.",
            "Indicators can be stale or misattributed.",
        ),
        "Validate the indicator's source and confidence, review all evidence referencing it, and "
        "escalate according to the incident response plan. Preserve the matched artefacts.",
        ("T1071",),
        Confidence.HIGH,
    ),
    _rule(
        "IOC_MATCH_HASH",
        "File hash matches a supplied indicator",
        "ioc",
        Severity.CRITICAL,
        "A SHA-256, SHA-1 or MD5 digest of a collected file matches an analyst-supplied indicator. "
        "Cryptographic hash matches are strong evidence that the file is the same artefact as the "
        "known sample, though the indicator's reputation must still be validated.",
        (
            "Hash collisions are impractical for SHA-256 but MD5/SHA-1 indicators should be "
            "treated with more caution.",
            "A benign tool may share a hash if the indicator was mislabelled.",
        ),
        "Preserve the file, confirm the indicator's provenance, and follow malware handling "
        "procedures. Do not upload the sample to external services without authorisation.",
        ("T1204",),
        Confidence.HIGH,
    ),
]

RULES: dict[str, Rule] = {rule.rule_id: rule for rule in _RULES}


def get_rule(rule_id: str) -> Rule:
    """Return a rule by ID, raising a clear error for typos."""
    try:
        return RULES[rule_id]
    except KeyError as exc:
        raise KeyError(f"unknown rule_id: {rule_id!r}") from exc


def rules_by_category() -> dict[str, list[Rule]]:
    """Group rules by category, useful for documentation and report appendices."""
    grouped: dict[str, list[Rule]] = {}
    for rule in _RULES:
        grouped.setdefault(rule.category, []).append(rule)
    return grouped
