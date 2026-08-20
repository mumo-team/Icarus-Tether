#!/usr/bin/env node
/**
 * Claude Desktop에 이 프록시를 MCP 서버로 등록한다. (macOS · Windows · Linux)
 *
 * 사용법 (저장소 어디서든):
 *   node proxy/scripts/setup-claude-desktop.mjs
 *   node proxy/scripts/setup-claude-desktop.mjs --remove
 *
 * ⚠️ 반드시 Claude Desktop을 완전히 종료한 뒤 실행할 것.
 * 앱이 켜져 있으면 자기 메모리 내용으로 설정 파일을 통째로 덮어써서,
 * 여기서 추가한 mcpServers 항목이 조용히 지워진다.
 *   macOS   : Cmd+Q
 *   Windows : 창을 닫는 것만으로는 부족하다. 작업표시줄 트레이 아이콘에서 종료할 것.
 */

import { readFileSync, writeFileSync, existsSync, copyFileSync, mkdirSync } from "node:fs";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join, delimiter } from "node:path";
import { homedir } from "node:os";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "../..");
const PROXY_ENTRY = join(REPO_ROOT, "proxy/src/index.ts");
const TSX_CLI = join(REPO_ROOT, "node_modules/tsx/dist/cli.mjs");

// ── 플랫폼별 차이는 전부 여기 모아둔다 ──────────────────────────────────
const PLATFORM = process.platform;

/** Claude Desktop 설정 파일 위치 */
function configPath() {
  if (PLATFORM === "darwin") {
    return join(homedir(), "Library/Application Support/Claude/claude_desktop_config.json");
  }
  if (PLATFORM === "win32") {
    // %APPDATA%가 없으면(드문 경우) 표준 경로로 계산한다
    const appData = process.env.APPDATA ?? join(homedir(), "AppData", "Roaming");
    return join(appData, "Claude", "claude_desktop_config.json");
  }
  return join(homedir(), ".config/Claude/claude_desktop_config.json"); // linux
}

/**
 * 앱이 켜져 있는가. 판단 못 하면 null을 돌려준다(막지 않고 경고만) —
 * 확인 실패로 셋업 자체를 못 하게 만들면 오히려 불편하기 때문.
 */
function isClaudeRunning() {
  try {
    if (PLATFORM === "darwin") {
      // pgrep -f는 macOS에서 이 프로세스를 놓치므로 osascript로 확인한다
      return execSync(`osascript -e 'application "Claude" is running'`, { encoding: "utf8" }).trim() === "true";
    }
    if (PLATFORM === "win32") {
      // /NH = 헤더 없음. 없으면 "INFO: No tasks..." 가 나오므로 실행파일명 포함 여부로 본다.
      const out = execSync(`tasklist /FI "IMAGENAME eq Claude.exe" /NH`, { encoding: "utf8" });
      return /claude\.exe/i.test(out);
    }
    return execSync(`pgrep -x Claude || true`, { encoding: "utf8" }).trim().length > 0;
  } catch {
    return null; // 확인 불가
  }
}

/** 자식 프로세스에 물려줄 PATH. node가 표준 경로 밖(nvm 등)에 있어도 찾게 한다. */
function childPath(nodeBin) {
  const nodeDir = dirname(nodeBin);
  if (PLATFORM === "win32") {
    const sys32 = join(process.env.SystemRoot ?? join("C:", "Windows"), "System32");
    return [nodeDir, sys32].join(delimiter);
  }
  return [nodeDir, "/usr/local/bin", "/usr/bin", "/bin"].join(delimiter);
}

/** 프록시 로그 위치 안내 */
function logHint() {
  if (PLATFORM === "darwin") {
    return "  tail -50 ~/Library/Logs/Claude/mcp-server-icarus-tether.log";
  }
  if (PLATFORM === "win32") {
    const p = ["%APPDATA%", "Claude", "logs", "mcp-server-icarus-tether.log"].join(String.fromCharCode(92));
    return `  Get-Content -Tail 50 "${p}"`;
  }
  return "  tail -50 ~/.config/Claude/logs/mcp-server-icarus-tether.log";
}

/** 종료 방법 안내 */
const QUIT_HINT =
  PLATFORM === "darwin"
    ? "   Cmd+Q로 완전히 종료한 뒤 다시 실행하세요."
    : PLATFORM === "win32"
      ? "   창을 닫는 것만으로는 부족합니다. 작업표시줄 트레이 아이콘 우클릭 → 종료 후 다시 실행하세요."
      : "   앱을 완전히 종료한 뒤 다시 실행하세요.";

const CONFIG_PATH = configPath();

// 1) 앱이 켜져 있으면 중단 — 켜진 채로 쓰면 앱이 자기 메모리 내용으로 설정을
//    덮어써서 여기서 추가한 등록이 조용히 사라진다.
const running = isClaudeRunning();
if (running === null) {
  console.error("⚠️ Claude Desktop 실행 여부를 확인하지 못했습니다. 종료 상태인지 직접 확인하세요.");
} else if (running) {
  console.error("❌ Claude Desktop이 실행 중입니다.");
  console.error(QUIT_HINT);
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
} else {
  // 앱을 한 번도 안 켰거나 설정이 없는 경우 — 디렉터리부터 만든다
  mkdirSync(dirname(CONFIG_PATH), { recursive: true });
  console.log(`설정 파일이 없어 새로 만듭니다: ${CONFIG_PATH}`);
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
      PATH: childPath(nodeBin),
      // 데모용 정책 설정(계보 판정 + HITL). 엔진 기본값(session/off)은 건드리지 않는다.
      TAINTGUARD_TOOL_REGISTRY: join(REPO_ROOT, "proxy/config/demo-registry.json"),
    },
  },
};

writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2) + "\n");

console.log("✅ Claude Desktop에 'icarus-tether' MCP 서버를 등록했습니다.");
console.log(`   플랫폼:   ${PLATFORM}`);
console.log(`   설정 파일: ${CONFIG_PATH}`);
console.log(`   command:  ${nodeBin}`);
console.log(`   proxy:    ${PROXY_ENTRY}`);
console.log("");
console.log("다음: Claude Desktop을 실행하고 이렇게 물어보세요.");
console.log('  "지금 쓸 수 있는 도구 뭐가 있어?"');
console.log("  → query_customer_db / fetch_web_page / send_email 3개가 보이면 성공");
console.log("");
console.log("문제가 있으면 로그를 확인하세요:");
console.log(logHint());
