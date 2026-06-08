#!/usr/bin/env bats
#
# 单元测试：聚焦不依赖 root/docker 的纯函数与文件生成逻辑。
# 运行：bats tests/
# 说明：@test 名称用 ASCII，避免老版本 bats 对非 ASCII 名称解析异常。

setup() {
  REPO="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
  # core.sh 提供 info/warn/die 与随机/交互工具函数
  source "$REPO/lib/core.sh"
}

# ---------- 随机密钥生成 ----------

@test "gen_secret: requested length, alnum only" {
  run gen_secret 24
  [ "$status" -eq 0 ]
  [ "${#output}" -eq 24 ]
  [[ "$output" =~ ^[A-Za-z0-9]+$ ]]
}

@test "gen_secret: default length is 24" {
  run gen_secret
  [ "${#output}" -eq 24 ]
}

@test "gen_password: requested length" {
  run gen_password 20
  [ "${#output}" -eq 20 ]
}

@test "gen_guid: braces + uppercase GUID" {
  run gen_guid
  [[ "$output" =~ ^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$ ]]
}

@test "gen_int: within [100000000, 999999999]" {
  run gen_int
  [[ "$output" =~ ^[0-9]+$ ]]
  [ "$output" -ge 100000000 ]
  [ "$output" -le 999999999 ]
}

# ---------- 交互提示 ----------

@test "prompt: empty input returns default" {
  local v=""
  prompt v "msg" "DEFVAL" </dev/null
  [ "$v" = "DEFVAL" ]
}

@test "prompt: returns typed value" {
  local v=""
  prompt v "msg" "DEF" <<<"typed"
  [ "$v" = "typed" ]
}

@test "prompt_port: rejects out-of-range, accepts valid" {
  local v=""
  prompt_port v "port" "" <<<$'99999\n20000\n'
  [ "$v" = "20000" ]
}

# ---------- seccomp ----------

@test "seccomp: valid JSON, ERRNO baseline, io_uring allowed" {
  source "$REPO/lib/seccomp.sh"
  local out="$BATS_TEST_TMPDIR/seccomp.json"
  generate_seccomp_profile "$out"
  run jq -e '.defaultAction == "SCMP_ACT_ERRNO"' "$out"
  [ "$status" -eq 0 ]
  run jq -e '[.syscalls[] | select(.action=="SCMP_ACT_ALLOW") | .names[]]
             | map(select(startswith("io_uring"))) | length == 3' "$out"
  [ "$status" -eq 0 ]
}

# ---------- compose 渲染 ----------

@test "write_compose_server: renders expected server compose" {
  source "$REPO/config.sh"
  APP_DIR="$BATS_TEST_TMPDIR/app"
  COMPOSE_FILE="$APP_DIR/docker-compose.yml"
  mkdir -p "$APP_DIR"
  source "$REPO/lib/compose.sh"

  write_compose_server "ghcr.io/test/openppp2:latest" "appsettings.json"

  grep -q "image: ghcr.io/test/openppp2:latest" "$COMPOSE_FILE"
  grep -q "network_mode: host" "$COMPOSE_FILE"
  grep -q "seccomp=./seccomp-openppp2.json" "$COMPOSE_FILE"
  grep -q -- "--mode=server" "$COMPOSE_FILE"
}

# ---------- Docker 安装：镜像源选择逻辑 ----------
# 通过桩函数记录 install_docker 实际尝试了哪些镜像源、以何顺序，
# 验证 DOCKER_INSTALL_MIRROR 的各取值与 auto 探测的回退顺序是否正确。

# 装载 docker.sh 并打桩：curl 写出非空脚本文件；get-docker 执行总是“失败”，
# 以便走完整个 order；apt/dnf/yum 渠道被禁用，使 install_docker 最终返回非 0。
_load_docker_with_stubs() {
  source "$REPO/lib/core.sh"
  source "$REPO/lib/docker.sh"

  ATTEMPTS=()

  # 只认 curl/timeout 存在；apt-get/dnf/yum/docker 一律“不存在”，从而停在渠道 1 之后。
  need_cmd() {
    case "$1" in
      curl | timeout) return 0 ;;
      *) return 1 ;;
    esac
  }
  # curl 桩：解析 -o <file> 并写入非空内容，使 [[ -s tmp_sh ]] 成立。
  curl() {
    local prev="" a
    for a in "$@"; do
      [[ "$prev" == "-o" ]] && printf 'get-docker-stub' >"$a"
      prev="$a"
    done
    return 0
  }
  # 记录每次实际尝试的镜像源（"" 记为 official），并恒定失败以遍历完 order。
  _run_get_docker_script() {
    local mirror="$2"
    ATTEMPTS+=("${mirror:-official}")
    return 1
  }
}

@test "install_docker: DOCKER_INSTALL_MIRROR=Aliyun only tries Aliyun" {
  _load_docker_with_stubs
  _download_docker_reachable() { return 0; }
  DOCKER_INSTALL_MIRROR="Aliyun"
  run install_docker
  [ "$status" -ne 0 ]            # 无任何渠道装上 docker
  [ "${#ATTEMPTS[@]}" -eq 1 ]
  [ "${ATTEMPTS[0]}" = "Aliyun" ]
}

@test "install_docker: DOCKER_INSTALL_MIRROR=none only tries official" {
  _load_docker_with_stubs
  DOCKER_INSTALL_MIRROR="none"
  run install_docker
  [ "${#ATTEMPTS[@]}" -eq 1 ]
  [ "${ATTEMPTS[0]}" = "official" ]
}

@test "install_docker: auto + official reachable => official first, then mirrors" {
  _load_docker_with_stubs
  _download_docker_reachable() { return 0; }
  DOCKER_INSTALL_MIRROR="auto"
  run install_docker
  [ "${ATTEMPTS[0]}" = "official" ]
  [ "${ATTEMPTS[1]}" = "Aliyun" ]
  [ "${ATTEMPTS[2]}" = "AzureChinaCloud" ]
}

@test "install_docker: auto + official unreachable => mirrors first (CN path)" {
  _load_docker_with_stubs
  _download_docker_reachable() { return 1; }   # 模拟国内：官方源不可达
  DOCKER_INSTALL_MIRROR="auto"
  run install_docker
  [ "${ATTEMPTS[0]}" = "Aliyun" ]
  [ "${ATTEMPTS[1]}" = "AzureChinaCloud" ]
  [ "${ATTEMPTS[2]}" = "official" ]
}

@test "_run_with_timeout: runs command, returns its status" {
  source "$REPO/lib/core.sh"
  source "$REPO/lib/docker.sh"
  run _run_with_timeout 5 true
  [ "$status" -eq 0 ]
  run _run_with_timeout 5 false
  [ "$status" -ne 0 ]
  # 0/空 超时值 => 不限时，直接执行
  run _run_with_timeout 0 true
  [ "$status" -eq 0 ]
}
