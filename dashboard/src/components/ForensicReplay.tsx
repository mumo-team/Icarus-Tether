import { useEffect, useMemo, useRef, useState } from "react";
import type { AuditLogEntry } from "@icarus-tether/types";
import TaintGraph, { type BlockedSink, type LineageSnapshot } from "./TaintGraph";
import { card, mono, pill } from "../theme";

// proxy는 판정을 방송한 '직후' 계보를 방송한다(index.ts: broadcastDecision → broadcastLineage).
// 그래서 스냅샷 시각 바로 앞의 판정이 곧 그 스냅샷을 만든 판정이다. 두 방송 사이의
// 간격은 밀리초 단위라, 시계 흔들림만 이만큼 봐주면 된다.
const SKEW_MS = 250;

/**
 * 이 스냅샷을 만든 판정이 차단이었는지 가려낸다.
 * 차단 로그만 훑으면 안 된다 — 그러면 통과 호출의 스냅샷에도 직전 차단이 따라붙는다.
 * 전체 로그에서 '스냅샷 직전 마지막 판정'을 찾고, 그게 BLOCKED일 때만 얹는다.
 */
function blockedAt(logs: AuditLogEntry[], snapshot: LineageSnapshot | undefined): BlockedSink | null {
  if (logs.length === 0) return null;
  const snapAt = snapshot?.timestamp ? Date.parse(snapshot.timestamp) : NaN;

  // 시각 없는 스냅샷(구버전 프레임)은 시간 매칭이 불가능하다. 최신 단계에서만,
  // 그것도 마지막 판정이 차단일 때만 얹어 오해를 만들지 않는다.
  if (Number.isNaN(snapAt)) {
    const recent = logs[logs.length - 1];
    return recent?.decision === "BLOCKED" ? { toolName: recent.toolName, timestamp: recent.timestamp } : null;
  }

  let latest: AuditLogEntry | null = null;
  let latestAt = -Infinity;
  for (const l of logs) {
    const at = Date.parse(l.timestamp);
    if (Number.isNaN(at) || at > snapAt + SKEW_MS) continue;
    if (at >= latestAt) {
      latest = l;
      latestAt = at;
    }
  }
  return latest?.decision === "BLOCKED" ? { toolName: latest.toolName, timestamp: latest.timestamp } : null;
}

// 오염 전파를 시간순으로 되감아 재생한다 — 포렌식 분석.
// proxy가 판정마다 보낸 계보 스냅샷을 쌓아둔 배열을 받아, 슬라이더/재생으로 훑는다.
// 감사 로그를 같이 받아, 그 단계에서 막힌 호출을 그래프 종단으로 얹는다.
export default function ForensicReplay({
  snapshots,
  logs,
}: {
  snapshots: LineageSnapshot[];
  logs: AuditLogEntry[];
}) {
  const [index, setIndex] = useState(0);
  const [playing, setPlaying] = useState(false);
  // 사용자가 슬라이더를 직접 만졌으면 라이브 자동추적을 멈춘다.
  const pinned = useRef(false);
  const last = Math.max(snapshots.length - 1, 0);

  // 새 스냅샷이 오면(라이브 진행) 최신으로 따라간다 — 단, 사용자가 되감아 본 뒤엔 멈춘다.
  useEffect(() => {
    if (!pinned.current) setIndex(last);
  }, [snapshots.length, last]);

  // 재생: 현재 위치부터 끝까지 한 단계씩.
  useEffect(() => {
    if (!playing) return;
    const timer = setInterval(() => {
      setIndex((i) => {
        if (i >= last) {
          setPlaying(false);
          return i;
        }
        return i + 1;
      });
    }, 900);
    return () => clearInterval(timer);
  }, [playing, last]);

  const snapshot = snapshots[index];
  const current = snapshot?.nodes ?? [];
  const isLive = index === last && !pinned.current;

  // 시각 없는 스냅샷은 최신 단계에서만 차단을 얹는다(blockedAt 주석 참고).
  const blocked = useMemo(() => {
    if (!snapshot?.timestamp && index !== last) return null;
    return blockedAt(logs, snapshot);
  }, [logs, snapshot, index, last]);

  return (
    // 앵커는 모달의 "문제가 된 데이터 출처 확인하기"가 scrollIntoView로 쓴다.
    <section id="taint-graph-panel" style={card}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
          flexWrap: "wrap",
          marginBottom: 16,
        }}
      >
        <h3>오염 계보</h3>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {blocked && <span style={pill("danger")}>이 단계에서 차단</span>}
          {isLive && (
            <span
              style={{
                ...mono,
                fontSize: 10,
                letterSpacing: "0.12em",
                color: "var(--untrusted)",
                padding: "3px 8px",
                borderRadius: 4,
                background: "rgba(155,208,235,.08)",
                border: "1px solid rgba(155,208,235,.26)",
              }}
            >
              LIVE
            </span>
          )}
        </div>
      </div>

      {snapshots.length === 0 ? (
        <div
          style={{
            padding: 22,
            textAlign: "center",
            borderRadius: "var(--r)",
            border: "1px dashed var(--line-2)",
            color: "var(--ink-3)",
            fontSize: 12,
          }}
        >
          아직 추적된 오염이 없습니다
        </div>
      ) : (
        <>
          <TaintGraph lineage={current} blocked={blocked} />

          <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 14, flexWrap: "wrap" }}>
            <button
              onClick={() => {
                pinned.current = true;
                setIndex((i) => Math.max(i - 1, 0));
              }}
              disabled={index === 0}
            >
              이전
            </button>
            <button
              style={{
                background: "rgba(155,208,235,.10)",
                borderColor: "var(--accent-line)",
                color: "var(--untrusted)",
              }}
              onClick={() => {
                if (playing) {
                  setPlaying(false);
                } else {
                  pinned.current = true;
                  if (index >= last) setIndex(0); // 끝이면 처음부터
                  setPlaying(true);
                }
              }}
            >
              {playing ? "정지" : "재생"}
            </button>
            <button
              onClick={() => {
                pinned.current = true;
                setIndex((i) => Math.min(i + 1, last));
              }}
              disabled={index === last}
            >
              다음
            </button>
            <button
              onClick={() => {
                pinned.current = false;
                setPlaying(false);
                setIndex(last);
              }}
              disabled={isLive}
            >
              최신으로
            </button>

            <input
              type="range"
              min={0}
              max={last}
              value={index}
              aria-label="오염 전파 단계"
              onChange={(e) => {
                pinned.current = true;
                setPlaying(false);
                setIndex(Number(e.target.value));
              }}
              style={{ flex: 1, minWidth: 120, accentColor: "var(--untrusted)", height: 6 }}
            />

            <span style={{ ...mono, fontSize: 11.5, color: "var(--ink-3)", minWidth: 132, textAlign: "right" }}>
              {index + 1} / {last + 1} 단계 · 노드 {current.length}개
              {blocked ? " · 차단 1건" : ""}
            </span>
          </div>
        </>
      )}
    </section>
  );
}
