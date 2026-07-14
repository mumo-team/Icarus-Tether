import { pipeline } from "@huggingface/transformers";

/**
 * ⚠️ 콘텐츠(fetch_web_page/read_email 등 UNTRUSTED_ORIGIN 결과) 전용.
 * 사용자 직접 명령문에는 쓰지 말 것 — 오탐률이 크게 올라감(테스트로 확인됨).
 *
 * 임계값은 샘플 5개짜리 소규모 테스트로 잡은 초안이다. 실전 투입 전
 * 더 많은 실제 데이터로 재검증 필요.
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

/** 서버 기동 시 미리 호출해서, 첫 실제 요청이 모델 다운로드/로딩까지 기다리지 않게 한다. */
export async function warmupInjectionDetector(): Promise<void> {
  await getClassifier();
}

export interface InjectionDetectionResult {
  /** 임계값을 넘는 인젝션 의심 여부. evaluated=false면 이 값을 신뢰하면 안 됨 */
  isInjection: boolean;
  /** INJECTION 라벨 원점수 (0~1) — 다중 신호 융합(B)에 넘길 원자료 */
  score: number;
  /** 모델 호출이 정상적으로 끝났는지 */
  evaluated: boolean;
}

/**
 * 비신뢰 출처 콘텐츠 하나를 검사한다.
 * 실패 시(모델 에러 등) isInjection:true로 fail-safe 처리 — 판정 불가를
 * 조용히 "안전"으로 넘기지 않는다 (policy-engine 5원칙의 "실패는 안전하게"와 동일 원칙).
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
    console.error("[injection-detect] 평가 실패 — fail-safe로 의심 처리:", err);
    return { isInjection: true, score: 1, evaluated: false };
  }
}