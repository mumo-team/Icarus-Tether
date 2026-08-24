import { useState,useEffect, useRef } from "react";
import type { AuditLogEntry, ApprovalRequest, PolicyDecision, UserAction, OutputScanEvent, OverrideAuditEntry } from "@icarus-tether/types";
import MetricCards from "./components/MetricCards";
import ThreatFusionBanner from "./components/ThreatFusionBanner";
import ApprovalQueue from "./components/ApprovalQueue";
import SanitizationCompareView from "./components/SanitizationCompareView";
import type { LineageNode } from "./components/TaintGraph";
import ForensicReplay from "./components/ForensicReplay";
import TrifectaApprovalModal from "./components/TrifectaApprovalModal";
import AuditTimeline from "./components/AuditTimeline";
import OutputScanPanel from "./components/OutputScanPanel";
import BlockReason from "./components/BlockReason";
import { card, inset, pill, GAP } from "./theme";

interface InjectionCheckEntry {
  id: string;
  sessionId: string;
  toolName: string;
  isInjection: boolean;
  score: number;
  timestamp: string;
  evaluated: boolean;
}

const SAMPLE_BLOCKED_DECISION: PolicyDecision = {
  sessionId: "demo-session-1",
  toolName: "send_email",
  allowed: false,
  matchedTags: [],
  canOverride: true,
  approvalId: "ap-1",
  explanation: {
    summary: "민감한 정보가 외부로 나가려는 흐름이 감지되어 전송을 막았어요.",
    reason: "고객 문의(query_customer_db)에서 나온 정보와 외부 웹 페이지 내용이 함께 섞여 있어요.",
    risks: [
      "외부에서 온 내용에 숨은 지시가 있으면, 민감한 정보가 의도치 않게 밖으로 새어 나갈 수 있어요.",
    ],
    actions: [
      {
        kind: "REQUEST_APPROVAL",
        label: "관리자 승인 받고 보내기",
        description: "담당자가 확인 후 승인하면 한 번만 전송이 허용돼요.",
        available: true,
        detail: "ap-1",
      },
    ],
  },
};
const MAX_EVENTS = 500;    // logs·injectionChecks·outputScans 슬라이딩 윈도우
const MAX_SNAPSHOTS = 100; // 계보 스냅샷은 매 이벤트마다 배열 전체를 쌓아 더 무거우므로 더 낮게

// 무한 append 방지 — 최근 max건만 유지한다.
function pushCapped<T>(prev: T[], next: T, max: number): T[] {
  const arr = [...prev, next];
  return arr.length > max ? arr.slice(arr.length - max) : arr;
}

export default function App() {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [modalDecision, setModalDecision] = useState<PolicyDecision | null>(null);
  const [injectionChecks, setInjectionChecks] = useState<InjectionCheckEntry[]>([]);
  const [hitlLog, setHitlLog] = useState<OverrideAuditEntry[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const [auditIntegrity, setAuditIntegrity] = useState<{
    ok: boolean;
    total: number;
    problems: { line: number; kind: string; detail: string }[];
  } | null>(null);
  const [sanitization, setSanitization] = useState<{
    method: string;
    originalTags: string[];
    resultTags: string[];
    ok: boolean;
    maskedCount?: number;
    residualSensitiveData?: boolean;
  } | null>(null);
  const [snapshots, setSnapshots] = useState<LineageNode[][]>([]);
  const [outputScans, setOutputScans] = useState<OutputScanEvent[]>([]);
  const [awaiting, setAwaiting] = useState<Record<string, "awaiting" | "timeout">>({});
  const [recvErrors, setRecvErrors] = useState(0);
  // 차단된 호출이 실제로 내보내려던 인자. 정화 전/후 비교의 좌측 상자 원본이 된다.
  const [blockedArgs, setBlockedArgs] = useState<string | null>(null);
    useEffect(() => {
    let disposed = false; // 언마운트 후 재연결 타이머가 되살아나는 것 방지
    let retryTimer: number | undefined;
    let ws: WebSocket | null = null;

    function connect() {
      // 브리지가 127.0.0.1에만 리슨하므로 주소를 맞춘다 — Windows에서 localhost가
      // ::1(IPv6)로 먼저 풀리면 연결이 지연되거나 실패할 수 있다.
      ws = new WebSocket("ws://127.0.0.1:7331");
      wsRef.current = ws;

      ws.onopen = () => {
        setWsConnected(true);
        console.log("[대시보드] proxy 연결됨");
      };

      ws.onmessage = (event) => {
        let data;
        try {
          data = JSON.parse(event.data);
        } catch (err) {
          // 조용히 멈추지 않는다 — 이 프레임만 건너뛰고 수신오류로 집계·표시.
          console.error("[대시보드] 이벤트 파싱 실패 — 이 프레임만 건너뜀:", err);
          setRecvErrors((n) => n + 1);
          return;
        }

        if (data.type === "decision") {
          const entry: AuditLogEntry = {
            id: `${data.sessionId}-${data.toolName}-${data.timestamp}`,
            sessionId: data.sessionId,
            toolName: data.toolName,
            decision: data.decision ?? (data.allowed ? "ALLOWED" : "BLOCKED"),
            matchedTags: data.matchedTags ?? [],
            timestamp: data.timestamp,
          };
          setLogs((prev) => pushCapped(prev, entry, MAX_EVENTS));
          // 차단 건에만 실려 온다(브리지가 통과 건은 안 싣는다).
          if (data.allowed === false && typeof data.blockedArgs === "string") {
            setBlockedArgs(data.blockedArgs);
          }
          if (data.outputScan) setOutputScans((prev) => pushCapped(prev, data.outputScan, MAX_EVENTS));
          // 승인 가능한 차단이 오면 모달을 자동으로 띄운다 — 발표 3단계 "와우 포인트".
          if (data.allowed === false && data.canOverride && data.approvalId) {
            // 이미 모달이 떠 있으면 덮어쓰지 않는다 — 새 건은 아래 큐에만 쌓인다(setApprovals).
            setModalDecision((cur) => cur ?? ({
              sessionId: data.sessionId,
              toolName: data.toolName,
              allowed: false,
              matchedTags: data.matchedTags ?? [],
              reason: data.reason,
              explanation: data.explanation,
              canOverride: data.canOverride,
              approvalId: data.approvalId,
            }));
            // 큐에도 동일 항목을 쌓는다 — 모달과 같은 데이터로 ApprovalQueue·대기 카운트를 살린다.
            // (broadcastDecision이 args를 안 실으므로 args는 비운다 — 큐는 도구명·상태만 표시.)
            setApprovals((prev) =>
              prev.some((a) => a.id === data.approvalId)
                ? prev
                : [
                    ...prev,
                    {
                      id: data.approvalId,
                      sessionId: data.sessionId,
                      toolName: data.toolName,
                      args: {},
                      status: "PENDING",
                      requestedAt: data.timestamp,
                    },
                  ]
            );
          }
        }
        if (data.type === "approval_resolved") {
          console.log(
            `[대시보드] 승인 처리됨: ${data.approvalId} → ${data.approved ? "승인" : "거부"}`
          );
          // 큐 항목 상태를 실제 처리 결과로 갱신 (모달·큐 어느 쪽으로 처리했든 반영).
          setApprovals((prev) =>
            prev.map((a) =>
              a.id === data.approvalId
                ? {
                    ...a,
                    status: data.approved ? "APPROVED" : "REJECTED",
                    resolvedAt: data.timestamp,
                    resolvedBy: data.resolvedBy,
                  }
                : a
            )
          );
          // 응답이 왔으니 이 항목의 '대기/무응답' 표시를 해제한다.
          setAwaiting((prev) => {
            const next = { ...prev };
            delete next[data.approvalId];
            return next;
          });
        }

        if (data.type === "injection_check") {
          const entry: InjectionCheckEntry = {
            id: `${data.sessionId}-${data.toolName}-${data.timestamp}`,
            sessionId: data.sessionId,
            toolName: data.toolName,
            isInjection: data.isInjection,
            score: data.score,
            timestamp: data.timestamp,
            evaluated: data.evaluated ?? true,
          };
          setInjectionChecks((prev) => pushCapped(prev, entry, MAX_EVENTS));
        }
        if (data.type === "audit_integrity") {
          setAuditIntegrity({ ok: data.ok, total: data.total, problems: data.problems ?? [] });
        }
        if (data.type === "sanitized") {
          console.log(
            `[대시보드] 정화됨(${data.method}): ${data.originalTags?.join(",")} → ${data.resultTags?.join(",") || "(없음)"}`
          );
          setSanitization({
            method: data.method,
            originalTags: data.originalTags ?? [],
            resultTags: data.resultTags ?? [],
            ok: data.ok,
            maskedCount: data.maskedCount,
            residualSensitiveData: data.residualSensitiveData,
          });
       }
        if (data.type === "lineage") {
          setSnapshots((prev) => pushCapped(prev, data.nodes ?? [], MAX_SNAPSHOTS));
        }
        if (data.type === "hitl_audit") {
          // 세션 전체 HITL 감사로그(엔진 누적) — append가 아니라 교체.
          setHitlLog(data.entries ?? []);
        }
      };

      // onerror 뒤에는 항상 onclose가 따라오므로, 재연결은 onclose 한 곳에서만 건다.
      ws.onerror = () => {};

      ws.onclose = () => {
        setWsConnected(false);
        wsRef.current = null;
        if (disposed) return;
        // proxy는 "데모 1회 = 1프로세스"라 실행할 때마다 죽고 새로 뜬다.
        // 계속 재시도해 두면 다음 데모 실행에 자동으로 다시 붙는다.
        retryTimer = window.setTimeout(connect, 1000);
      };
    }

    connect();

    return () => {
      disposed = true;
      if (retryTimer !== undefined) window.clearTimeout(retryTimer);
      wsRef.current = null;
      ws?.close();
    };
  }, []);

    function handleDecide(id: string, status: "APPROVED" | "REJECTED", resolvedBy: string) {
    // 큐 버튼도 엔진까지 전달한다 — 승인 상태는 proxy 프로세스의 엔진 메모리에 있어
    // 브라우저가 직접 못 부르므로, 모달 경로(handleActionClick)와 동일하게 WS로 보낸다.
    const ws = wsRef.current;
    const appr = approvals.find((a) => a.id === id);
    if (ws && ws.readyState === WebSocket.OPEN && appr) {
      ws.send(
        JSON.stringify({
          type: status === "APPROVED" ? "approve" : "reject",
          sessionId: appr.sessionId,
          approvalId: id,
          resolvedBy,
        })
      );
    }
    // 낙관적 승인표시 제거: 엔진이 OVERRIDE_STALE로 승인을 무효화할 수 있어
    // 로컬에서 미리 확정하지 않는다. 상태 확정은 approval_resolved 수신 시에만.
    // 큐에는 '전송됨·응답 대기'만 표시하고, 5초 내 응답 없으면 '응답 없음'으로 전환.
    setAwaiting((prev) => ({ ...prev, [id]: "awaiting" }));
    window.setTimeout(() => {
      setAwaiting((prev) => (prev[id] === "awaiting" ? { ...prev, [id]: "timeout" } : prev));
    }, 5000);
  }

   function handleActionClick(action: UserAction) {
    const ws = wsRef.current;
    const wsOpen = ws && ws.readyState === WebSocket.OPEN;
    if (action.kind === "REQUEST_APPROVAL" && modalDecision) {
      // 규약 4-4: REQUEST_APPROVAL 액션의 detail이 approvalId다. 한 결정에 승인 액션이
      // 둘 이상 실릴 수 있어, decision 단위 값보다 액션 단위 값이 정확하다.
      // (detail이 없는 경우에만 decision 쪽으로 되돌아간다.)
      const approvalId = action.detail ?? modalDecision.approvalId;
      if (!approvalId) {
        console.error("[대시보드] 승인 id가 없어 승인을 보낼 수 없습니다");
      } else if (wsOpen) {
        // 승인 상태는 proxy 프로세스의 엔진 메모리에 있어 브라우저가 직접 못 부른다.
        // 웹소켓으로 보내면 proxy가 같은 프로세스에서 resolveApproval을 대신 호출한다.
        ws.send(
          JSON.stringify({
            type: "approve",
            sessionId: modalDecision.sessionId,
            approvalId,
            resolvedBy: "dashboard-reviewer",
          })
        );
        console.log("[대시보드] 승인 전송:", approvalId);
      } else {
        console.error("[대시보드] proxy 연결이 없어 승인을 보낼 수 없습니다");
      }
    } else if (action.kind === "SANITIZE" && modalDecision?.sessionId) {
      // action.detail에 정화 방법(TOKENIZATION / STRUCTURED_EXTRACTION)이 들어있다.
      // proxy가 attemptSanitization으로 세션 태그를 해제 → 재시도하면 통과된다.
      if (wsOpen) {
        ws.send(
          JSON.stringify({
            type: "sanitize",
            sessionId: modalDecision.sessionId,
            method: action.detail,
          })
        );
        console.log("[대시보드] 정화 요청:", action.detail);
      } else {
        console.error("[대시보드] proxy 연결이 없어 정화를 요청할 수 없습니다");
      } 
    } else if (action.kind === "INSPECT_SOURCE") {
      document.getElementById("taint-graph-panel")?.scrollIntoView({ behavior: "smooth" });
    } else {
      console.log("[대시보드] 아직 미배선 액션:", action.kind, action.label);
    }
    setModalDecision(null);
  }

  const lastLineage = snapshots[snapshots.length - 1] ?? [];

  return (
    <div style={{ maxWidth: 1340, margin: "0 auto", padding: "26px 30px 76px" }}>
      {/* ── 상단 ─────────────────────────────────────── */}
      <nav
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 20,
          flexWrap: "wrap",
          paddingBottom: 20,
          marginBottom: 24,
          borderBottom: "1px solid var(--line)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span
            style={{
              width: 30,
              height: 30,
              borderRadius: "var(--r2)",
              display: "grid",
              placeItems: "center",
              background: "linear-gradient(150deg, var(--untrusted), var(--sensitive-deep))",
            }}
          >
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="var(--ground)" strokeWidth="2.4" strokeLinecap="round">
              <path d="M12 3v6.4M12 14.6V21" />
              <circle cx="12" cy="12" r="2.2" fill="var(--ground)" stroke="none" />
              <path d="M5 7.5 8.6 10M19 7.5 15.4 10M5 16.5 8.6 14M19 16.5 15.4 14" />
            </svg>
          </span>
          <h1>Icarus-Tether 대시보드</h1>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          {recvErrors > 0 && (
            <span style={pill("danger")}>이벤트 수신 오류 {recvErrors}건</span>
          )}
          <span
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 9,
              padding: "7px 14px",
              borderRadius: "var(--r2)",
              fontSize: 12.5,
              fontWeight: 500,
              background: wsConnected ? "var(--ok-bg)" : "rgba(255,255,255,.05)",
              border: `1px solid ${wsConnected ? "var(--ok-line)" : "var(--line-2)"}`,
              color: wsConnected ? "var(--ok)" : "var(--ink-3)",
            }}
          >
            <span
              style={{
                width: 6,
                height: 6,
                borderRadius: "50%",
                background: wsConnected ? "var(--ok)" : "var(--ink-3)",
              }}
            />
            {wsConnected ? "proxy 연결됨" : "proxy 대기 중"}
          </span>
        </div>
      </nav>

      <MetricCards logs={logs} approvals={approvals} />

      {/* ── 계보가 화면의 주인공. 근거·승인은 옆에 붙인다 ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1.82fr 1fr", gap: GAP, alignItems: "stretch", marginBottom: GAP }}>
        <ForensicReplay snapshots={snapshots} />
        <aside style={card}>
          <BlockReason logs={logs} lineage={lastLineage} />
          <div style={{ height: 1, background: "var(--line)", margin: "18px 0 15px" }} />
          <ApprovalQueue approvals={approvals} onDecide={handleDecide} awaiting={awaiting} />
        </aside>
      </div>

      <div style={{ marginBottom: GAP }}>
        <SanitizationCompareView
          sanitization={sanitization}
          logs={logs}
          lineage={lastLineage}
          blockedArgs={blockedArgs}
        />
      </div>

      {/* 판정에 관여하지 않는 신호라 작게 둔다 — 크게 띄우면 "AI가 막는다"로 읽힌다 */}
      <ThreatFusionBanner logs={logs} injectionChecks={injectionChecks} />

      {/* 기록 — 사후 조회용이라 접어 둔다. 접어야 첫 화면이 한 스크린에 들어온다 */}
      <details style={{ ...card, padding: 0, overflow: "hidden" }}>
        <summary style={{ padding: "15px 22px", fontSize: 13, color: "var(--ink-2)" }}>기록</summary>
        <div style={{ padding: "0 22px 20px", display: "grid", gap: GAP }}>
          <AuditTimeline logs={logs} hitlLog={hitlLog} />

          <div
            style={{
              ...inset,
              padding: "12px 15px",
              display: "flex",
              alignItems: "center",
              gap: 12,
              fontSize: 12.5,
              flexWrap: "wrap",
              borderColor: !auditIntegrity ? "var(--line)" : auditIntegrity.ok ? "var(--ok-line)" : "var(--danger-line)",
            }}
          >
            <span style={pill(!auditIntegrity ? "muted" : auditIntegrity.ok ? "ok" : "danger")}>무결성</span>
            {!auditIntegrity ? (
              <span style={{ color: "var(--ink-3)" }}>기록이 쌓이면 매 판정마다 검증됩니다</span>
            ) : auditIntegrity.ok ? (
              <span style={{ color: "var(--ink-2)" }}>
                감사 로그 <b className="mono">{auditIntegrity.total}</b>줄 전부 서명·체인 정상
              </span>
            ) : (
              <span style={{ color: "var(--danger-hi)" }}>
                위변조 {auditIntegrity.problems.length}건 (전체 {auditIntegrity.total}줄)
                <ul style={{ margin: "6px 0 0" }}>
                  {auditIntegrity.problems.map((p, i) => (
                    <li key={i} className="mono" style={{ fontSize: 11.5 }}>
                      {p.line}번째 줄 [{p.kind}] {p.detail}
                    </li>
                  ))}
                </ul>
              </span>
            )}
          </div>

          {injectionChecks.length > 0 && (
            <div style={{ display: "grid", gap: 8 }}>
              {injectionChecks.map((c) => (
                <div
                  key={c.id}
                  style={{ ...inset, padding: "11px 14px", display: "flex", alignItems: "center", gap: 12, fontSize: 12.5 }}
                >
                  <span style={pill(!c.evaluated ? "muted" : c.isInjection ? "danger" : "ok")}>
                    {!c.evaluated ? "평가 실패" : c.isInjection ? "위험" : "안전"}
                  </span>
                  <span className="mono" style={{ color: "var(--ink-2)" }}>
                    {c.toolName} · score={c.score.toFixed(4)}
                  </span>
                  <em
                    style={{
                      marginLeft: "auto",
                      fontStyle: "normal",
                      fontSize: 9,
                      padding: "1px 5px",
                      borderRadius: 3,
                      background: "rgba(255,255,255,.08)",
                      color: "var(--ink-3)",
                    }}
                  >
                    관측용
                  </em>
                </div>
              ))}
            </div>
          )}

          <OutputScanPanel scans={outputScans} />
        </div>
      </details>

      {modalDecision && (
        <TrifectaApprovalModal
          decision={modalDecision}
          onActionClick={handleActionClick}
          onClose={() => setModalDecision(null)}
          queuedCount={approvals.filter((a) => a.status === "PENDING" && a.id !== modalDecision.approvalId).length}
        />
      )}

      {import.meta.env.DEV && (
        <div style={{ marginTop: 32, paddingTop: 16, borderTop: "1px solid var(--line)" }}>
          <button onClick={() => setModalDecision(SAMPLE_BLOCKED_DECISION)}>
            트라이펙타 경고 데모 보기 (샘플 · 개발용)
          </button>
        </div>
      )}
    </div>
  );
}
