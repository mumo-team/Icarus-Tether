import { useEffect, useRef, useState } from "react";
import TaintGraph, { type LineageNode } from "./TaintGraph";

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
    <section>
      <h2>오염 전파 포렌식 리플레이</h2>
      {snapshots.length === 0 ? (
        <p style={{ color: "#888", fontSize: "14px" }}>
          데모를 실행하면 오염이 전파되는 과정을 단계별로 되감아 볼 수 있습니다.
        </p>
      ) : (
        <>
          <div style={{ display: "flex", alignItems: "center", gap: "10px", margin: "8px 0" }}>
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
            <input
              type="range"
              min={0}
              max={last}
              value={index}
              onChange={(e) => {
                pinned.current = true;
                setPlaying(false);
                setIndex(Number(e.target.value));
              }}
              style={{ flex: 1, accentColor: "#5f5e5a", height: "6px" }}
            />
            <span style={{ fontSize: "13px", minWidth: "120px", textAlign: "right" }}>
              {index + 1} / {last + 1} 단계 · 노드 {current.length}개
              {isLive && <span style={{ color: "#2e7d32", marginLeft: "6px" }}>[라이브]</span>}
            </span>
          </div>
          <button
            onClick={() => {
              pinned.current = false;
              setPlaying(false);
              setIndex(last);
            }}
            style={{ fontSize: "12px", marginBottom: "8px" }}
          >
            최신으로 (라이브 따라가기)
          </button>
          <TaintGraph lineage={current} />
        </>
      )}
    </section>
  );
}