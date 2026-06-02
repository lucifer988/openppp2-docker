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
