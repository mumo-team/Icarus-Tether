/**
 * 인라인 스타일에서 재사용하는 조각들.
 *
 * 이 저장소의 대시보드는 CSS 파일 없이 인라인 style로 쓰여 있다.
 * 인라인은 외부 CSS로 덮어쓸 수 없으므로 테마를 얹으려면 값 자체를
 * 바꿔야 한다. 색·형태는 theme.css의 커스텀 프로퍼티를 var()로 참조하고
 * (인라인 style에서도 var()가 그대로 동작한다), 반복되는 덩어리만
 * 여기에 모아 둔다.
 */

import type { CSSProperties } from "react";

/** 판정 결과에 따른 상태색 — 통과/차단 두 가지뿐이다 */
export const STATE = {
  ok: { fg: "var(--ok)", bg: "var(--ok-bg)", line: "var(--ok-line)" },
  danger: { fg: "var(--danger-hi)", bg: "var(--danger-bg)", line: "var(--danger-line)" },
  muted: { fg: "var(--ink-3)", bg: "rgba(255,255,255,.05)", line: "var(--line-2)" },
} as const;

export type StateKey = keyof typeof STATE;

/** 카드 — 화면의 기본 표면 */
export const card: CSSProperties = {
  background: "var(--panel)",
  border: "1px solid var(--line)",
  borderRadius: "var(--R)",
  padding: "20px 22px",
};

/** 카드 안쪽에 한 단계 파인 면 (코드 블록·노드·빈 상태 등) */
export const inset: CSSProperties = {
  background: "var(--panel-2)",
  border: "1px solid var(--line)",
  borderRadius: "var(--r)",
};

/** 상태 알약 — 통과/차단처럼 결과를 한 단어로 보여줄 때 */
export function pill(state: StateKey): CSSProperties {
  const s = STATE[state];
  return {
    display: "inline-block",
    padding: "3px 9px",
    borderRadius: 999,
    fontSize: 10.5,
    fontWeight: 500,
    background: s.bg,
    border: `1px solid ${s.line}`,
    color: s.fg,
  };
}

/** 고정폭 — 도구 이름·해시·숫자처럼 자릿수가 의미를 갖는 값 */
export const mono: CSSProperties = {
  fontFamily: '"IBM Plex Mono", ui-monospace, monospace',
  fontVariantNumeric: "tabular-nums",
  letterSpacing: 0,
};

/** 섹션 사이 여백 — 카드끼리는 12px로 붙인다 */
export const GAP = 12;

/**
 * 오염 축의 색. 색상각이 아니라 채도로 구분한다 — 축마다 다른 색을 주면
 * "민감 = 위험"으로 읽혀서 정당한 조회가 나쁜 동작처럼 보인다.
 */
export const AXIS = {
  UNTRUSTED_ORIGIN: { fg: "var(--untrusted)", deep: "var(--untrusted-deep)", hi: "var(--untrusted-hi)" },
  SENSITIVE: { fg: "var(--sensitive)", deep: "var(--sensitive-deep)", hi: "var(--sensitive-hi)" },
  SINK: { fg: "var(--sink)", deep: "var(--sink-deep)", hi: "var(--sensitive-hi)" },
  SYSTEM: { fg: "var(--system)", deep: "var(--system-deep)", hi: "var(--ink-2)" },
} as const;

/** 태그 이름 → 축 색. 모르는 태그는 시스템(무채색)으로 떨어뜨린다 */
export function axisOf(tag: string) {
  if (tag.includes("UNTRUSTED")) return AXIS.UNTRUSTED_ORIGIN;
  if (tag.includes("SENSITIVE")) return AXIS.SENSITIVE;
  return AXIS.SYSTEM;
}
