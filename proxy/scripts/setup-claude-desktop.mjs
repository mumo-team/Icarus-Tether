#!/usr/bin/env node
/**
 * Claude Desktop에 이 프록시를 MCP 서버로 등록한다.
 *
 * 사용법 (저장소 어디서든):
 *   node proxy/scripts/setup-claude-desktop.mjs
 *
 * ⚠️ 반드시 Claude Desktop을 완전히 종료(Cmd+Q)한 뒤 실행할 것.
 * 앱이 켜져 있으면 자기 메모리 내용으로 설정 파일을 통째로 덮어써서,
 * 여기서 추가한 mcpServers 항목이 조용히 지워진다.
 */

import { readFileSync, writeFileSync, existsSync, copyFileSync } from "node:fs";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join } from "node:path";
import { homedir } from "node:os";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "../..");
const PROXY_ENTRY = join(REPO_ROOT, "proxy/src/index.ts");
const TSX_CLI = join(REPO_ROOT, "node_modules/tsx/dist/cli.mjs");
const CONFIG_PATH = join(
  homedir(),
  "Library/Application Support/Claude/claude_desktop_config.json"
);

// 1) 앱이 켜져 있으면 중단 — 켜진 채로 쓰면 앱이 자기 메모리 내용으로 설정을
//    덮어써서 여기서 추가한 등록이 조용히 사라진다.
//    (pgrep -f는 macOS에서 이 프로세스를 놓치므로 osascript로 확인한다)
let claudeRunning = false;
try {
  claudeRunning =
    execSync(`osascript -e 'application "Claude" is running'`, {
      encoding: "utf8",
    }).trim() === "true";
} catch {
  console.error("⚠️ Claude Desktop 실행 여부를 확인하지 못했습니다. 종료 상태인지 직접 확인하세요.");
}
if (claudeRunning) {
  console.error("❌ Claude Desktop이 실행 중입니다.");
  console.error("   Cmd+Q로 완전히 종료한 뒤 다시 실행하세요.");
  console.error("   (켜져 있으면 앱이 설정 파일을 덮어써서 등록이 지워집니다)");
  process.exit(1);
}

// 2) 필요한 파일 확인
for (const [label, p] of [
  ["프록시 진입점", PROXY_ENTRY],
  ["tsx 실행파일", TSX_CLI],
]) {
  if (!existsSync(p)) {
    console.error(`❌ ${label}을 찾을 수 없습니다: ${p}`);
    console.error("   저장소 루트에서 먼저 `npm install && npm run build`를 실행하세요.");
    process.exit(1);
  }
}

// 3) 기존 설정 백업 후 읽기
let config = {};
if (existsSync(CONFIG_PATH)) {
  config = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
  const backup = `${CONFIG_PATH}.backup-${Date.now()}`;
  copyFileSync(CONFIG_PATH, backup);
  console.log(`백업 생성: ${backup}`);
}

// 3-1) --remove: 등록만 지우고 끝낸다 (다른 설정은 손대지 않음)
if (process.argv.includes("--remove")) {
  if (config.mcpServers?.["icarus-tether"]) {
    delete config.mcpServers["icarus-tether"];
    if (Object.keys(config.mcpServers).length === 0) delete config.mcpServers;
    writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2) + "\n");
    console.log("✅ 'icarus-tether' 등록을 제거했습니다. Claude Desktop을 다시 실행하세요.");
  } else {
    console.log("등록된 'icarus-tether'가 없습니다. (이미 제거됨)");
  }
  process.exit(0);
}

// 4) mcpServers만 병합 (기존 preferences 등은 그대로 둔다)
// nvm 등으로 node가 표준 경로 밖에 있을 수 있으므로 전부 절대경로로 적는다.
const nodeBin = process.execPath;
config.mcpServers = {
  ...(config.mcpServers ?? {}),
  "icarus-tether": {
    command: nodeBin,
    args: [TSX_CLI, PROXY_ENTRY],
    env: {
      PATH: `${dirname(nodeBin)}:/usr/local/bin:/usr/bin:/bin`,
      // 데모용 정책 설정(계보 판정 + HITL). 엔진 기본값(session/off)은 건드리지 않는다.
      TAINTGUARD_TOOL_REGISTRY: join(REPO_ROOT, "proxy/config/demo-registry.json"),
    },
  },
};

writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2) + "\n");

console.log("✅ Claude Desktop에 'icarus-tether' MCP 서버를 등록했습니다.");
console.log(`   설정 파일: ${CONFIG_PATH}`);
console.log(`   command:  ${nodeBin}`);
console.log(`   proxy:    ${PROXY_ENTRY}`);
console.log("");
console.log("다음: Claude Desktop을 실행하고 이렇게 물어보세요.");
console.log('  "지금 쓸 수 있는 도구 뭐가 있어?"');
console.log("  → query_customer_db / fetch_web_page / send_email 3개가 보이면 성공");
console.log("");
console.log("문제가 있으면 로그를 확인하세요:");
console.log("  tail -50 ~/Library/Logs/Claude/mcp-server-icarus-tether.log");
