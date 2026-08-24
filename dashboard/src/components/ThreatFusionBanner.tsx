import { useMemo } from "react";
import { ToolRiskTag, type AuditLogEntry } from "@icarus-tether/types";
import { mono } from "../theme";

// 융합에 쓰는 최소 신호 — 대시보드가 이미 받는 것에서 파생한다(새 state 없음).
interface InjectionSignal {
  isInjection: boolean;
  score: number;
  /** 모델 호출이 정상 종료했는지. false면 isInjection은 fail-safe 기본값이라 신뢰 불가 */
  evaluated: boolean;
}

/**
 * 여러 독립 신호를 한 줄로 종합해 보여준다.
 *
 * 화면에서 일부러 작게 둔다 — 이 판정은 차단에 관여하지 않는다. 크게 띄우면
 * "AI가 종합 판단해서 막는다"로 읽혀서, 판정 경로에 AI가 없다는 이 제품의
 * 논지를 화면이 스스로 흔든다. 실제 차단은 policy-engine 소관이다.
 */
export default function ThreatFusionBanner({
  logs,
  injectionChecks,
}: {
  logs: AuditLogEntry[];
  injectionChecks: InjectionSignal[];
}) {
  const fusion = useMemo(() => {
    const lastBlocked = [...logs].reverse().find((l) => l.decision === "BLOCKED");
    const tags = lastBlocked?.matchedTags ?? [];
    const lastInjection = injectionChecks[injectionChecks.length - 1];

    const signalLineage = tags.length > 0;
    const signalTrifecta = tags.includes(ToolRiskTag.SENSITIVE) && tags.includes(ToolRiskTag.UNTRUSTED_ORIGIN);
    // evaluated=false는 모델 로드/추론 실패 시의 fail-safe 반환값(isInjection:true, score:1)이다.
    // 그대로 켜면 '모델 실패'가 화면에서 '탐지 성공'으로 둔갑한다 — 평가된 건만 신호로 센다.
    const signalInjection = (lastInjection?.evaluated ?? false) && lastInjection.isInjection;

    const count = [signalLineage, signalTrifecta, signalInjection].filter(Boolean).length;
    const level = count >= 3 ? "높음" : count >= 1 ? "주의" : "정상";

    return { tags, toolName: lastBlocked?.toolName, lastInjection, signalLineage, signalTrifecta, signalInjection, level };
  }, [logs, injectionChecks]);

  const inj = fusion.lastInjection;
  const injUnknown = !!inj && !inj.evaluated;

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 9,
        flexWrap: "wrap",
        padding: "13px 18px",
        borderRadius: "var(--R)",
        background: "var(--panel-2)",
        border: "1px solid var(--line)",
        marginBottom: 12,
      }}
    >
      <span style={{ fontSize: 12, color: "var(--ink-3)", marginRight: 3 }}>신호</span>

      <Chip on={fusion.signalLineage} label="계보 오염" value={fusion.signalLineage ? fusion.tags.join(" + ") : "없음"} />
      <Chip
        on={fusion.signalTrifecta}
        label="트라이펙타"
        value={fusion.signalTrifecta ? `성립 · ${fusion.toolName}` : "미성립"}
      />
      <Chip
        on={fusion.signalInjection}
        unknown={injUnknown}
        label="ML 인젝션"
        value={!inj ? "이력 없음" : injUnknown ? "판정 불가" : inj.score.toFixed(4)}
        note="관측용"
      />

      <span style={{ marginLeft: "auto", fontSize: 11.5, color: "var(--ink-3)" }}>
        종합 <b style={{ color: fusion.level === "정상" ? "var(--ink-2)" : "var(--ink)" }}>{fusion.level}</b>
      </span>
    </div>
  );
}

/** unknown=true는 "신호를 얻지 못함" — 신호가 없는 '정상'과 반드시 구분한다.
 *  판정 불가를 '정상'으로 적으면 화면이 근거 없는 안심을 준다. */
function Chip({
  on,
  label,
  value,
  note,
  unknown = false,
}: {
  on: boolean;
  label: string;
  value: string;
  note?: string;
  unknown?: boolean;
}) {
  const active = on || unknown;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 7,
        padding: "6px 11px",
        borderRadius: "var(--r2)",
        fontSize: 11.5,
        background: "rgba(255,255,255,.04)",
        border: `1px solid ${active ? "var(--danger-line)" : "var(--line-2)"}`,
        color: active ? "var(--danger-hi)" : "var(--ink-2)",
      }}
    >
      {label}
      <b style={{ ...mono, fontSize: 11, color: active ? "var(--danger)" : "var(--ink)" }}>{value}</b>
      {note && (
        <em
          style={{
            fontStyle: "normal",
            fontSize: 9,
            padding: "1px 5px",
            borderRadius: 3,
            background: "rgba(255,255,255,.08)",
            color: "var(--ink-3)",
          }}
        >
          {note}
        </em>
      )}
    </span>
  );
}
