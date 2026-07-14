/**
 * 사용자용 설명 계층 — 결정론 번역만. AI/LLM 호출 0.
 *
 * "사실"(태그·연결 weak 여부·정화 가능성·canOverride — 전부 이미 결정론적으로
 * 계산된 값)을 미리 정의된 한국어 템플릿에 매핑한다. 조건 분기와 문자열 조립뿐,
 * 판단이 낄 자리가 없다.
 *
 * 노출 규칙:
 * - summary/reason/risks/label/description: 사람 말만. 기술 용어(SENSITIVE,
 *   TOKENIZATION, tn_노드id, trifecta 등) 금지 — explain.test.ts가 regex로 강제.
 * - detail: 기계용 필드(approvalId, SanitizationMethod) — 여기만 기술 값 허용.
 * - 노드 id는 절대 노출하지 않고 "라벨(도구명)"로 — 라벨은 config.toolLabels에서,
 *   없으면 도구 이름 그대로 폴백.
 */

import {
  ToolRiskTag,
  SanitizationMethod,
  type UserAction,
  type UserFacingExplanation,
} from "@icarus-tether/types";
import { getPolicyConfig } from "./config.js";
import type { LineageEvidence } from "./shadow.js";

// ---------------------------------------------------------------------------
// 템플릿 (전부 미리 정의 — 결정론)
// ---------------------------------------------------------------------------

const TAG_PHRASE: Record<ToolRiskTag, string> = {
  [ToolRiskTag.SENSITIVE]: "민감한 정보(비밀번호·개인정보 등)",
  [ToolRiskTag.UNTRUSTED_ORIGIN]: "외부에서 온 신뢰할 수 없는 내용",
};

const SUMMARY_BLOCKED = "민감한 정보가 외부로 나가려는 흐름이 감지되어 전송을 막았어요.";

const RISK_INJECTION =
  "외부에서 온 내용에 숨은 지시가 있으면, 민감한 정보가 의도치 않게 밖으로 새어 나갈 수 있어요.";
const RISK_WEAK_ONLY =
  "다만 이 연관은 시간상 겹침으로 추정된 것이라, 실제로는 서로 무관한 데이터일 수도 있어요.";
const RISK_STRONG =
  "이 데이터들은 명확하게 연결되어 있어서 유출 위험이 높아요.";

function toolLabelOf(toolName: string): string {
  const label = getPolicyConfig().toolLabels[toolName];
  return label ? `${label}(${toolName})` : toolName;
}

// ---------------------------------------------------------------------------
// 조립
// ---------------------------------------------------------------------------

export interface ExplainInput {
  evidence: LineageEvidence;
  argTags: ToolRiskTag[];
  canOverride: boolean;
  approvalId?: string;
}

export function buildUserExplanation(input: ExplainInput): UserFacingExplanation {
  const { evidence, argTags, canOverride, approvalId } = input;

  // 사실 수집 (전부 결정론적으로 이미 계산된 값)
  const unionTags = new Set<ToolRiskTag>([...evidence.unionTags, ...argTags]);
  const taintedNodes = evidence.nodes.filter((n) => n.tags.length > 0);
  const allWeak = taintedNodes.every((n) => n.weak) && argTags.length === 0;

  // reason: "무엇이 어디서 와서 섞여 있는지" — 도구는 라벨로, 노드 id 노출 없음
  const sourceParts: string[] = taintedNodes.map(
    (n) => `「${toolLabelOf(n.toolName)}」에서 온 ${n.tags.map((t) => TAG_PHRASE[t]).join("과 ")}`
  );
  if (argTags.length > 0) {
    sourceParts.push(`이번 요청에 직접 실려 온 ${argTags.map((t) => TAG_PHRASE[t]).join("과 ")}`);
  }
  const reason =
    sourceParts.length > 0
      ? `이 데이터에 ${sourceParts.join(", 그리고 ")}이 섞여 있어요.`
      : "이 데이터의 출처를 안전하다고 확인할 수 없었어요.";

  // risks: 사실 → 문구
  const risks: string[] = [RISK_INJECTION];
  risks.push(allWeak ? RISK_WEAK_ONLY : RISK_STRONG);

  // actions: 실제로 가능한 것만 available (사실로만 결정)
  const actions: UserAction[] = [];

  if (unionTags.has(ToolRiskTag.SENSITIVE)) {
    actions.push({
      kind: "SANITIZE",
      label: "민감 정보를 가리고 보내기",
      description: "이름·이메일 같은 개인정보와 비밀 값을 익명 토큰으로 바꿔서 보냅니다.",
      available: true,
      detail: SanitizationMethod.TOKENIZATION,
    });
  }
  if (unionTags.has(ToolRiskTag.UNTRUSTED_ORIGIN)) {
    actions.push({
      kind: "SANITIZE",
      label: "외부 내용에서 안전한 항목만 추려 보내기",
      description:
        "외부에서 온 내용 전체 대신, 정해진 형식의 값(제목·유형 등)만 추출해 위험한 내용이 담길 자리를 없앱니다.",
      available: true,
      detail: SanitizationMethod.STRUCTURED_EXTRACTION,
    });
  }

  actions.push(
    canOverride && approvalId
      ? {
          kind: "REQUEST_APPROVAL",
          label: "관리자 승인 받고 보내기",
          description:
            "이 차단은 확실하지 않은 연관(시간상 겹침 추정)에 근거해요. 관리자가 확인 후 이번 한 번만 통과를 승인할 수 있습니다.",
          available: true,
          detail: approvalId,
        }
      : {
          kind: "REQUEST_APPROVAL",
          label: "관리자 승인 받고 보내기",
          description:
            "데이터 연결이 명확해서 승인으로는 열 수 없어요. 민감 정보를 가리거나 안전한 항목만 추려서 다시 시도해 주세요.",
          available: false,
        }
  );

  actions.push({
    kind: "INSPECT_SOURCE",
    label: "문제가 된 데이터 출처 확인하기",
    description:
      taintedNodes.length > 0
        ? `이 데이터는 ${taintedNodes.map((n) => `「${toolLabelOf(n.toolName)}」`).join(", ")}의 결과와 연결되어 있어요.`
        : "이 요청의 데이터 흐름을 확인할 수 있어요.",
    available: true,
  });

  return { summary: SUMMARY_BLOCKED, reason, risks, actions };
}

/** fail-safe 차단용 — 계산 실패라 근거(evidence)가 없을 때의 단순 설명 */
export function buildFailSafeExplanation(): UserFacingExplanation {
  return {
    summary: "안전 확인을 마치지 못해서 일단 전송을 막았어요.",
    reason: "데이터의 출처를 확인하는 과정에서 문제가 생겨, 안전을 위해 보내지 않았어요.",
    risks: ["확인되지 않은 데이터를 내보내면 민감한 정보가 새어 나갈 수 있어요."],
    actions: [
      {
        kind: "INSPECT_SOURCE",
        label: "문제가 된 데이터 출처 확인하기",
        description: "이 요청의 데이터 흐름을 확인할 수 있어요.",
        available: true,
      },
    ],
  };
}
