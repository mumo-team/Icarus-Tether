import { useEffect, useRef, useState } from "react";
import TaintGraph, { type LineageNode } from "./TaintGraph";
import { card, mono } from "../theme";

// 오염 전파를 시간순으로 되감아 재생한다 — 포렌식 분석.
// proxy가 판정마다 보낸 계보 스냅샷을 쌓아둔 배열을 받아, 슬라이더/재생으로 훑는다.
export default function ForensicReplay({ snapshots }: { snapshots: LineageNode[][] }) {
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

  const current = snapshots[index] ?? [];
  const isLive = index === last && !pinned.current;

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
          <TaintGraph lineage={current} />

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
            </span>
          </div>
        </>
      )}
    </section>
  );
}
