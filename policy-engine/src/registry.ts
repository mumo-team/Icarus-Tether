/**
 * ToolRegistry — 도구 정적 분류를 설정 파일(JSON)에서 읽는다.
 *
 * 설정 파일 경로 우선순위:
 *   1. loadToolRegistry(filePath) 인자
 *   2. 환경변수 TAINTGUARD_TOOL_REGISTRY
 *   3. 기본값: <policy-engine>/config/tool-registry.json
 *
 * 보안 게이트웨이 특성상 설정이 없거나 형식이 틀리면 조용히 기본값으로
 * 돌아가지 않고 예외를 던진다(fail-closed).
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { SinkClass } from "@taintguard/types";

export interface ToolRegistry {
  sensitiveSources: ReadonlySet<string>;
  untrustedSources: ReadonlySet<string>;
  sinks: ReadonlyMap<string, SinkClass>;
}

// src/ 와 dist/ 어디서 실행되든 <policy-engine>/config 을 가리킨다
const DEFAULT_REGISTRY_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "config",
  "tool-registry.json"
);

const VALID_SINK_CLASSES = new Set<string>(Object.values(SinkClass));

function assertStringArray(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || !value.every((v) => typeof v === "string")) {
    throw new Error(`[tool-registry] "${field}"는 문자열 배열이어야 합니다`);
  }
  return value;
}

export function loadToolRegistry(
  filePath: string = process.env.TAINTGUARD_TOOL_REGISTRY ?? DEFAULT_REGISTRY_PATH
): ToolRegistry {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(filePath, "utf8"));
  } catch (err) {
    throw new Error(
      `[tool-registry] 설정 파일을 읽을 수 없습니다: ${filePath} (${(err as Error).message})`
    );
  }

  if (typeof raw !== "object" || raw === null) {
    throw new Error(`[tool-registry] 최상위 값은 객체여야 합니다: ${filePath}`);
  }
  const obj = raw as Record<string, unknown>;

  const sensitiveSources = new Set(assertStringArray(obj.sensitiveSources, "sensitiveSources"));
  const untrustedSources = new Set(assertStringArray(obj.untrustedSources, "untrustedSources"));

  if (typeof obj.sinks !== "object" || obj.sinks === null || Array.isArray(obj.sinks)) {
    throw new Error(`[tool-registry] "sinks"는 { 도구이름: SinkClass } 객체여야 합니다`);
  }
  const sinks = new Map<string, SinkClass>();
  for (const [toolName, sinkClass] of Object.entries(obj.sinks as Record<string, unknown>)) {
    if (typeof sinkClass !== "string" || !VALID_SINK_CLASSES.has(sinkClass)) {
      throw new Error(
        `[tool-registry] sinks["${toolName}"] 값 "${String(sinkClass)}"는 유효한 SinkClass가 아닙니다 (${[...VALID_SINK_CLASSES].join(", ")})`
      );
    }
    sinks.set(toolName, sinkClass as SinkClass);
  }

  return { sensitiveSources, untrustedSources, sinks };
}

let cached: ToolRegistry | null = null;

/** 프로세스당 1회 로드해 캐시한다. */
export function getToolRegistry(): ToolRegistry {
  cached ??= loadToolRegistry();
  return cached;
}
