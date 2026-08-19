/**
 * Phase 3 검증: 정책 핫리로드.
 * 프록시 실행 중에 설정 파일을 바꾸면 (1) 재시작 없이 반영되고, (2) 잘못된 설정으로 바꾸면
 * 기존 정책을 유지한 채 에러만 로그하는지 확인한다.
 *
 * MCP 핸드셰이크는 필요 없다 — 프록시 stderr의 핫리로드 로그만 관찰한다.
 */

import { spawn } from "node:child_process";
import { writeFileSync, readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROXY_PATH = resolve(__dirname, "../src/index.ts");
const TSX_CLI = resolve(__dirname, "../../node_modules/tsx/dist/cli.mjs");
const BASE_REGISTRY = resolve(__dirname, "../config/demo-registry.json");

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function main() {
  // 감시 대상이 될 임시 설정 파일 (실제 config는 안 건드림)
  const dir = mkdtempSync(join(tmpdir(), "icarus-hotreload-"));
  const cfgPath = join(dir, "registry.json");
  const baseCfg = readFileSync(BASE_REGISTRY, "utf8");
  writeFileSync(cfgPath, baseCfg);

  const child = spawn(process.execPath, [TSX_CLI, PROXY_PATH], {
    env: { ...process.env, TAINTGUARD_TOOL_REGISTRY: cfgPath },
    stdio: ["pipe", "pipe", "pipe"],
  });

  let log = "";
  child.stderr.on("data", (d: Buffer) => {
    log += d.toString();
    process.stderr.write(d);
  });

  const waitFor = async (needle: string, ms: number): Promise<boolean> => {
    const start = log.length;
    for (let i = 0; i < ms / 50; i++) {
      if (log.slice(start === 0 ? 0 : 0).includes(needle)) return true;
      await sleep(50);
    }
    return log.includes(needle);
  };

  // 프록시 기동 + 감시 시작 대기
  const watching = await waitFor("정책 파일 감시 시작", 8000);

  // (1) 정상 변경 → 핫리로드 적용
  const before = log.length;
  const changed = JSON.parse(baseCfg);
  changed.hitlPolicy = "off"; // 유효한 변경
  writeFileSync(cfgPath, JSON.stringify(changed, null, 2));
  await sleep(600);
  const applied = log.slice(before).includes("정책 핫리로드 적용됨");

  // (2) 잘못된 변경 → 리로드 실패, 기존 유지
  const before2 = log.length;
  writeFileSync(cfgPath, "{ 이건 깨진 JSON ");
  await sleep(600);
  const keptOnError = log.slice(before2).includes("정책 리로드 실패");

  child.kill();
  const pass = watching && applied && keptOnError;
  console.error(
    `\n[hotreload] 감시시작=${watching} 정상변경적용=${applied} 오류시기존유지=${keptOnError}`
  );
  console.error(`${pass ? "✅ PASS" : "❌ FAIL"} — 정책 핫리로드 (재시작 없이 반영 + 오류 격리)`);
  process.exit(pass ? 0 : 1);
}

main().catch((e) => {
  console.error("[hotreload] 실패:", e);
  process.exit(1);
});
