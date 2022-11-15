// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT

// Object class and permissions declarations live here
use crate::ast::CascadeString;
use crate::internal_rep::ClassList;
use sexp::{Atom, Sexp};

const COMMON_FILE_SOCK_PERMS: &[&str] = &[
    "ioctl",
    "read",
    "write",
    "create",
    "getattr",
    "setattr",
    "lock",
    "relabelfrom",
    "relabelto",
    "append",
    "map",
];

const COMMON_FILE_PERMS: &[&str] = &[
    "unlink",
    "link",
    "rename",
    "execute",
    "quotaon",
    "mounton",
    "audit_access",
    "open",
    "execmod",
    "watch",
    "watch_mount",
    "watch_sb",
    "watch_with_perm",
    "watch_reads",
];

const COMMON_SOCK_PERMS: &[&str] = &[
    "bind",
    "connect",
    "listen",
    "accept",
    "getopt",
    "setopt",
    "shutdown",
    "recvfrom",
    "sendto",
    "name_bind",
];

const COMMON_IPC_PERMS: &[&str] = &[
    "create",
    "destroy",
    "getattr",
    "setattr",
    "read",
    "write",
    "associate",
    "unix_read",
    "unix_write",
];

const COMMON_CAP_PERMS: &[&str] = &[
    "chown",
    "dac_override",
    "dac_read_search",
    "fowner",
    "fsetid",
    "kill",
    "setgid",
    "setuid",
    "setpcap",
    "linux_immutable",
    "net_bind_service",
    "net_broadcast",
    "net_admin",
    "net_raw",
    "ipc_lock",
    "ipc_owner",
    "sys_module",
    "sys_rawio",
    "sys_chroot",
    "sys_ptrace",
    "sys_pacct",
    "sys_admin",
    "sys_boot",
    "sys_nice",
    "sys_resource",
    "sys_time",
    "sys_tty_config",
    "mknod",
    "lease",
    "audit_write",
    "audit_control",
    "setfcap",
];

const COMMON_CAP2_PERMS: &[&str] = &[
    "mac_override",
    "mac_admin",
    "syslog",
    "wake_alarm",
    "block_suspend",
    "audit_read",
    "perfmon",
    "bpf",
    "checkpoint_restore",
];

pub fn make_classlist() -> ClassList<'static> {
    let mut classlist = ClassList::new();

    classlist.add_class(
        "security",
        vec![
            "compute_av",
            "compute_create",
            "compute_member",
            "check_context",
            "load_policy",
            "compute_relabel",
            "compute_user",
            "setenforce",
            "setbool",
            "setsecparam",
            "setcheckreqprot",
            "read_policy",
            "validate_trans",
        ],
    );

    classlist.add_class(
        "process",
        vec![
            "fork",
            "transition",
            "sigchld",
            "sigkill",
            "sigstop",
            "signull",
            "signal",
            "ptrace",
            "getsched",
            "setsched",
            "getsession",
            "getpgid",
            "setpgid",
            "getcap",
            "setcap",
            "share",
            "getattr",
            "setexec",
            "setfscreate",
            "noatsecure",
            "siginh",
            "setrlimit",
            "rlimitinh",
            "dyntransition",
            "setcurrent",
            "execmem",
            "execstack",
            "execheap",
            "setkeycreate",
            "setsockcreate",
            "getrlimit",
        ],
    );
    classlist.set_collapsed("process", "process2");

    classlist.add_class("process2", vec!["nnp_transition", "nosuid_transition"]);

    classlist.add_class(
        "system",
        vec![
            "ipc_info",
            "syslog_read",
            "syslog_mod",
            "syslog_console",
            "module_request",
            "module_load",
            // systemd permissions
            "halt",
            "reboot",
            "status",
            "start",
            "stop",
            "enable",
            "disable",
            "reload",
        ],
    );

    classlist.add_class("capability", COMMON_CAP_PERMS.to_vec());
    classlist.set_collapsed("capability", "capability2");

    classlist.add_class(
        "filesystem",
        vec![
            "mount",
            "remount",
            "unmount",
            "getattr",
            "relabelfrom",
            "relabelto",
            "associate",
            "quotamod",
            "quotaget",
            "watch",
        ],
    );

    classlist.add_class(
        "file",
        [
            COMMON_FILE_SOCK_PERMS,
            COMMON_FILE_PERMS,
            &["execute_no_trans", "entrypoint"],
        ]
        .concat(),
    );

    classlist.add_class(
        "dir",
        [
            COMMON_FILE_SOCK_PERMS,
            COMMON_FILE_PERMS,
            &["add_name", "remove_name", "reparent", "search", "rmdir"],
        ]
        .concat(),
    );

    classlist.add_class("fd", vec!["use"]);

    classlist.add_class(
        "lnk_file",
        [COMMON_FILE_SOCK_PERMS, COMMON_FILE_PERMS].concat(),
    );
    classlist.add_class(
        "chr_file",
        [COMMON_FILE_SOCK_PERMS, COMMON_FILE_PERMS].concat(),
    );
    classlist.add_class(
        "blk_file",
        [COMMON_FILE_SOCK_PERMS, COMMON_FILE_PERMS].concat(),
    );
    classlist.add_class(
        "sock_file",
        [COMMON_FILE_SOCK_PERMS, COMMON_FILE_PERMS].concat(),
    );
    classlist.add_class(
        "fifo_file",
        [COMMON_FILE_SOCK_PERMS, COMMON_FILE_PERMS].concat(),
    );
    classlist.add_class(
        "socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );

    classlist.add_class(
        "tcp_socket",
        [
            COMMON_FILE_SOCK_PERMS,
            COMMON_SOCK_PERMS,
            &["node_bind", "name_connect"],
        ]
        .concat(),
    );
    classlist.add_class(
        "udp_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS, &["node_bind"]].concat(),
    );
    classlist.add_class(
        "node_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS, &["node_bind"]].concat(),
    );
    classlist.add_class(
        "rawip_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS, &["node_bind"]].concat(),
    );
    classlist.add_class("node", vec!["recvfrom", "sendto"]);
    classlist.add_class("netif", vec!["ingress", "egress"]);
    classlist.add_class(
        "netlink_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "packet_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "key_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "unix_stream_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS, &["connectto"]].concat(),
    );
    classlist.add_class(
        "unix_dgram_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class("sem", COMMON_IPC_PERMS.to_vec());
    classlist.add_class("msg", vec!["send", "receive"]);
    classlist.add_class("msgq", [COMMON_IPC_PERMS, &["enqueue"]].concat());
    classlist.add_class("shm", [COMMON_IPC_PERMS, &["lock"]].concat());
    classlist.add_class("ipc", COMMON_IPC_PERMS.to_vec());
    classlist.add_class(
        "netlink_route_socket",
        [
            COMMON_FILE_SOCK_PERMS,
            COMMON_SOCK_PERMS,
            &["nlmsg_read", "nlmsg_write"],
        ]
        .concat(),
    );
    classlist.add_class(
        "netlink_tcpdiag_socket",
        [
            COMMON_FILE_SOCK_PERMS,
            COMMON_SOCK_PERMS,
            &["nlmsg_read", "nlmsg_write"],
        ]
        .concat(),
    );
    classlist.add_class(
        "netlink_nflog_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "netlink_xfrm_socket",
        [
            COMMON_FILE_SOCK_PERMS,
            COMMON_SOCK_PERMS,
            &["nlmsg_read", "nlmsg_write"],
        ]
        .concat(),
    );
    classlist.add_class(
        "netlink_selinux_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "netlink_iscsi_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "netlink_audit_socket",
        [
            COMMON_FILE_SOCK_PERMS,
            COMMON_SOCK_PERMS,
            &[
                "nlmsg_read",
                "nlmsg_write",
                "nlmsg_relay",
                "nlmsg_readpriv",
                "nlmsg_tty_audit",
            ],
        ]
        .concat(),
    );
    classlist.add_class(
        "netlink_fib_lookup_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "netlink_connector_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "netlink_netfilter_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "netlink_dnrt_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "association",
        vec!["sendto", "recvfrom", "setcontext", "polmatch"],
    );
    classlist.add_class(
        "netlink_kobject_uevent_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "netlink_generic_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "netlink_scsitransport_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "netlink_rdma_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "netlink_crypto_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "appletalk_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "packet",
        vec!["send", "recv", "relabelto", "forward_in", "forward_out"],
    );
    classlist.add_class(
        "key",
        vec![
            "view", "read", "write", "search", "link", "setattr", "create",
        ],
    );
    classlist.add_class(
        "dccp_socket",
        [
            COMMON_FILE_SOCK_PERMS,
            COMMON_SOCK_PERMS,
            &["node_bind", "name_connect"],
        ]
        .concat(),
    );
    classlist.add_class("memprotect", vec!["mmap_zero"]);
    classlist.add_class("peer", vec!["recv"]);
    classlist.add_class("capability2", COMMON_CAP2_PERMS.to_vec());
    classlist.add_class("kernel_service", vec!["use_as_override", "create_files_as"]);
    classlist.add_class(
        "tun_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS, &["attach_queue"]].concat(),
    );
    classlist.add_class(
        "binder",
        vec!["impersonate", "call", "set_context_mgr", "transfer"],
    );
    classlist.add_class("cap_userns", COMMON_CAP_PERMS.to_vec());
    classlist.add_class("cap2_userns", COMMON_CAP2_PERMS.to_vec());
    classlist.set_collapsed("cap_userns", "cap2_userns");
    classlist.add_class(
        "sctp_socket",
        [
            COMMON_FILE_SOCK_PERMS,
            COMMON_SOCK_PERMS,
            &["node_bind", "name_connect", "association"],
        ]
        .concat(),
    );
    classlist.add_class(
        "icmp_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS, &["node_bind"]].concat(),
    );
    classlist.add_class(
        "ax25_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "ipx_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "netrom_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "atmpvc_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "x25_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "rose_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "decnet_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "atmsvc_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "rds_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "irda_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "pppox_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "llc_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "can_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "tipc_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "bluetooth_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "iucv_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "rxrpc_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "isdn_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "phonet_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "ieee802154_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "caif_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "alg_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "nfc_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "vsock_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "kcm_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "qipcrtr_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "smc_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class("infiniband_pkey", vec!["access"]);
    classlist.add_class("infiniband_endpoint", vec!["manage_subnet"]);
    classlist.add_class(
        "bpf",
        vec![
            "map_create",
            "map_read",
            "map_write",
            "prog_load",
            "prog_run",
        ],
    );
    classlist.add_class(
        "xdp_socket",
        [COMMON_FILE_SOCK_PERMS, COMMON_SOCK_PERMS].concat(),
    );
    classlist.add_class(
        "perf_event",
        vec!["open", "cpu", "kernel", "tracepoint", "read", "write"],
    );
    classlist.add_class("lockdown", vec!["integrity", "confidentiality"]);
    classlist.add_class(
        "anon_inode",
        [COMMON_FILE_SOCK_PERMS, COMMON_FILE_PERMS].concat(),
    );

    //Userspace
    classlist.add_class("dbus", vec!["acquire_svc", "send_msg"]);
    classlist.add_class(
        "service",
        vec!["start", "stop", "status", "reload", "enable", "disable"],
    );

    classlist
}

pub fn perm_list_to_sexp(perms: &[CascadeString]) -> Vec<sexp::Sexp> {
    if perms.iter().any(|p| p == "*") {
        vec![Sexp::Atom(Atom::S("(all)".to_string()))]
    } else {
        perms
            .iter()
            .map(|p| Sexp::Atom(Atom::S(p.to_string())))
            .collect()
    }
}
