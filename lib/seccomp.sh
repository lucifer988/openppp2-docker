#!/usr/bin/env bash
# seccomp.sh - 生成 seccomp 安全策略
#
# 设计取舍：openppp2 使用 io_uring，而部分发行版的 Docker 默认 seccomp 会拒绝
# io_uring 相关调用，导致 "Operation not permitted"。为兼顾“可用”与“有防护”，
# 本策略采用「默认放行 + 显式拒绝高危调用」模型：
#   - 默认放行（不会因白名单不全而把 ppp 跑挂）；
#   - 显式拒绝一组与容器无关的高危系统调用（加载内核模块、reboot、kexec、
#     mount/pivot_root、ptrace 他进程等）；
#   - io_uring_setup/io_uring_enter/io_uring_register 始终放行。
# 如需排查问题，可临时改用 `--security-opt seccomp=unconfined`。

generate_seccomp_profile() {
  local out="$1"
  info "生成 seccomp 安全策略：$out"
  cat > "$out" <<'EOF'
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "archMap": [
    { "architecture": "SCMP_ARCH_X86_64",  "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"] }
  ],
  "syscalls": [
    {
      "names": [
        "acct", "add_key", "bpf", "clock_adjtime", "clock_settime",
        "create_module", "delete_module", "finit_module", "get_kernel_syms",
        "init_module", "ioperm", "iopl", "kcmp", "kexec_file_load",
        "kexec_load", "keyctl", "lookup_dcookie", "mount", "move_pages",
        "name_to_handle_at", "nfsservctl", "open_by_handle_at",
        "perf_event_open", "pivot_root", "ptrace", "query_module",
        "quotactl", "reboot", "request_key", "setns", "settimeofday",
        "stime", "swapoff", "swapon", "_sysctl", "umount", "umount2",
        "unshare", "uselib", "userfaultfd", "ustat", "vm86", "vm86old"
      ],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1
    },
    {
      "names": ["io_uring_setup", "io_uring_enter", "io_uring_register"],
      "action": "SCMP_ACT_ALLOW",
      "comment": "openppp2 依赖 io_uring，必须放行"
    }
  ]
}
EOF
}
