/**
 * 인젝션 탐지 — C 담당.
 *
 * ⚠️ 비신뢰 출처 콘텐츠(fetch_web_page·read_email 등 UNTRUSTED_ORIGIN 결과) 전용.
 * 사용자 직접 명령문에는 쓰지 말 것 — 오탐률이 크게 올라감(테스트로 확인됨).
 *
 * 역할은 "점수 산출"까지다. 최종 차단/허용 판정은 policy-engine(B) 소관 —
 * 여기서 나온 score는 대시보드에 방송만 하고 판정에는 관여하지 않는다.
 */

import { pipeline } from "@huggingface/transformers";
import { getPolicyConfig } from "@icarus-tether/policy-engine";
import { broadcastToDashboard } from "./dashboard-bridge.js";

/**
 * 임계값은 샘플 5개짜리 소규모 테스트로 잡은 초안이다.
 * 실전 투입 전 더 많은 실제 데이터로 재검증 필요.
 */
export const INJECTION_THRESHOLD = 0.95;

// DeBERTa 계열 토크나이저 한계(대략 512토큰) 대비 안전 마진.
// 안 자르면 라이브러리가 조용히 뒷부분을 버릴 수 있어, "인젝션이 문서
// 뒷부분에 있으면 못 본다"는 눈에 안 보이는 구멍이 생긴다.
const MAX_INPUT_CHARS = 2000;

type ClassifierResult = { label: string; score: number };

let classifierPromise: ReturnType<typeof pipeline> | null = null;
function getClassifier() {
  if (!classifierPromise) {
    classifierPromise = pipeline(
      "text-classification",
      "protectai/deberta-v3-base-prompt-injection-v2"
    );
  }
  return classifierPromise;
}

/** 기동 시 미리 호출해 두면, 첫 실제 요청이 모델 다운로드/로딩까지 기다리지 않는다. */
export async function warmupInjectionDetector(): Promise<void> {
  await getClassifier();
}

export interface InjectionDetectionResult {
  /** 임계값을 넘는 인젝션 의심 여부. evaluated=false면 이 값을 신뢰하면 안 됨 */
  isInjection: boolean;
  /** INJECTION 라벨 원점수 (0~1) — 다중 신호 융합에 넘길 원자료 */
  score: number;
  /** 모델 호출이 정상적으로 끝났는지 */
  evaluated: boolean;
}

/**
 * 비신뢰 출처 콘텐츠 하나를 검사한다.
 * 실패 시(모델 에러 등) isInjection:true로 fail-safe — 판정 불가를 조용히
 * "안전"으로 넘기지 않는다.
 */
export async function detectInjection(text: string): Promise<InjectionDetectionResult> {
  if (!text || text.trim().length === 0) {
    return { isInjection: false, score: 0, evaluated: true };
  }

  const truncated = text.length > MAX_INPUT_CHARS ? text.slice(0, MAX_INPUT_CHARS) : text;

  try {
    const classifier = await getClassifier();
    const result = (await classifier(truncated, { top_k: null })) as ClassifierResult[];
    const injectionScore = result.find((r) => r.label === "INJECTION")?.score ?? 0;
    return {
      isInjection: injectionScore > INJECTION_THRESHOLD,
      score: injectionScore,
      evaluated: true,
    };
  } catch (err) {
    console.error("[injection] 평가 실패 — fail-safe로 의심 처리:", err);
    return { isInjection: true, score: 1, evaluated: false };
  }
}

/** MCP 도구 결과에서 text 콘텐츠만 이어 붙인다. */
function extractText(result: unknown): string {
  const content = (result as { content?: Array<{ type: string; text?: string }> }).content;
  if (!Array.isArray(content)) return "";
  return content
    .filter((c) => c.type === "text" && typeof c.text === "string")
    .map((c) => c.text as string)
    .join("\n");
}

/**
 * 도구 결과 하나를 검사하고 결과를 대시보드에 방송한다.
 *
 * 검사 대상은 설정(untrustedSourceTools)이 정한다 — 도구 이름을 코드에 박지 않는다.
 * demo-registry 기준으로 fetch_web_page·read_email이 대상이다.
 * 대상이 아니면 아무 일도 하지 않으므로, 호출부는 조건 없이 부르면 된다.
 */
export async function checkInjection(
  sessionId: string,
  toolName: string,
  result: unknown
): Promise<void> {
  if (!getPolicyConfig().untrustedSourceTools.has(toolName)) return;

  const detection = await detectInjection(extractText(result));
  console.error(
    `[injection] 🔍 ${toolName}  score=${detection.score.toFixed(4)}  isInjection=${detection.isInjection}`
  );
  broadcastToDashboard({
    type: "injection_check",
    sessionId,
    toolName,
    isInjection: detection.isInjection,
    score: detection.score,
    evaluated: detection.evaluated,
    timestamp: new Date().toISOString(),
  });
}