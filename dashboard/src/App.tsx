import { useState,useEffect, useRef } from "react";
import type { AuditLogEntry, ApprovalRequest, PolicyDecision, UserAction } from "@icarus-tether/types";
import MetricCards from "./components/MetricCards";
import TrifectaWarningBanner from "./components/TrifectaWarningBanner";
import ThreatFusionBanner from "./components/ThreatFusionBanner";
import EventLogTimeline from "./components/EventLogTimeline";
import ApprovalQueue from "./components/ApprovalQueue";
import SanitizationCompareView from "./components/SanitizationCompareView";
import { type LineageNode } from "./components/TaintGraph";
import ForensicReplay from "./components/ForensicReplay";
import TrifectaApprovalModal from "./components/TrifectaApprovalModal";
import AuditTimeline, { type HitlAuditEntry } from "./components/AuditTimeline";

interface InjectionCheckEntry {
  id: string;
  sessionId: string;
  toolName: string;
  isInjection: boolean;
  score: number;
  timestamp: string;
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

export default function App() {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [modalDecision, setModalDecision] = useState<PolicyDecision | null>(null);
  const [injectionChecks, setInjectionChecks] = useState<InjectionCheckEntry[]>([]);
  const [hitlLog, setHitlLog] = useState<HitlAuditEntry[]>([]);
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
  } | null>(null);
  const [snapshots, setSnapshots] = useState<LineageNode[][]>([]);

    useEffect(() => {
    let disposed = false; // 언마운트 후 재연결 타이머가 되살아나는 것 방지
    let retryTimer: number | undefined;
    let ws: WebSocket | null = null;

    function connect() {
      ws = new WebSocket("ws://localhost:7331");
      wsRef.current = ws;

      ws.onopen = () => {
        setWsConnected(true);
        console.log("[대시보드] proxy 연결됨");
      };

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);

        if (data.type === "decision") {
          const entry: AuditLogEntry = {
            id: `${data.sessionId}-${data.toolName}-${data.timestamp}`,
            sessionId: data.sessionId,
            toolName: data.toolName,
            decision: data.allowed ? "ALLOWED" : "BLOCKED",
            matchedTags: data.matchedTags ?? [],
            timestamp: data.timestamp,
          };
          setLogs((prev) => [...prev, entry]);
          // 승인 가능한 차단이 오면 모달을 자동으로 띄운다 — 발표 3단계 "와우 포인트".
          if (data.allowed === false && data.canOverride && data.approvalId) {
            setModalDecision({
              sessionId: data.sessionId,
              toolName: data.toolName,
              allowed: false,
              matchedTags: data.matchedTags ?? [],
              reason: data.reason,
              explanation: data.explanation,
              canOverride: data.canOverride,
              approvalId: data.approvalId,
            });
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
        }

        if (data.type === "injection_check") {
          const entry: InjectionCheckEntry = {
            id: `${data.sessionId}-${data.toolName}-${data.timestamp}`,
            sessionId: data.sessionId,
            toolName: data.toolName,
            isInjection: data.isInjection,
            score: data.score,
            timestamp: data.timestamp,
          };
          setInjectionChecks((prev) => [...prev, entry]);
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
          });
       }
        if (data.type === "lineage") {
          setSnapshots((prev) => [...prev, data.nodes ?? []]);
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
    setApprovals((prev) =>
      prev.map((a) =>
        a.id === id
          ? { ...a, status, resolvedAt: new Date().toISOString(), resolvedBy }
          : a
      )
    );
  }

   function handleActionClick(action: UserAction) {
    const ws = wsRef.current;
    const wsOpen = ws && ws.readyState === WebSocket.OPEN;
    if (action.kind === "REQUEST_APPROVAL" && modalDecision?.approvalId) {
      if (wsOpen) {
        // 승인 상태는 proxy 프로세스의 엔진 메모리에 있어 브라우저가 직접 못 부른다.
        // 웹소켓으로 보내면 proxy가 같은 프로세스에서 resolveApproval을 대신 호출한다.
        ws.send(
          JSON.stringify({
            type: "approve",
            sessionId: modalDecision.sessionId,
            approvalId: modalDecision.approvalId,
            resolvedBy: "dashboard-reviewer",
          })
        );
        console.log("[대시보드] 승인 전송:", modalDecision.approvalId);
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
    } else {
      console.log("[대시보드] 아직 미배선 액션:", action.kind, action.label);
    }
    setModalDecision(null);
  }

  return (
    <div style={{ fontFamily: "sans-serif", padding: "24px" }}>
      <h1>Icarus-Tether 대시보드</h1>
       <button onClick={() => setModalDecision(SAMPLE_BLOCKED_DECISION)}>
         트라이펙타 경고 데모 보기 (샘플)
      </button>
      <p style={{ color: wsConnected ? "#2e7d32" : "#d32f2f", fontWeight: "bold" }}>
        {wsConnected ? "[연결됨] proxy 연결됨" : "[대기] proxy 대기 중 — 데모를 실행하면 자동 연결됩니다"}
      </p>
      <ThreatFusionBanner logs={logs} injectionChecks={injectionChecks} />
      <TrifectaWarningBanner logs={logs} />
      <MetricCards logs={logs} approvals={approvals} />
      <EventLogTimeline logs={logs} />
      <AuditTimeline logs={logs} hitlLog={hitlLog} />
      <section
        style={{
          margin: "12px 0",
          padding: "12px 16px",
          borderRadius: "8px",
          border: "2px solid",
          borderColor: !auditIntegrity ? "#9e9e9e" : auditIntegrity.ok ? "#2e7d32" : "#d32f2f",
          background: !auditIntegrity ? "#f5f5f5" : auditIntegrity.ok ? "#e8f5e9" : "#ffebee",
        }}
      >
        <strong>[무결성] 감사 로그</strong>{" "}
        {!auditIntegrity ? (
          <span style={{ color: "#616161" }}>세션 종료 시 검증됩니다</span>
        ) : auditIntegrity.ok ? (
          <span style={{ color: "#2e7d32" }}>
            [정상] 무결 — {auditIntegrity.total}줄 전부 서명·체인 정상
          </span>
        ) : (
          <span style={{ color: "#d32f2f" }}>
            [위반] 위변조 감지 — {auditIntegrity.problems.length}건 (전체 {auditIntegrity.total}줄)
            <ul style={{ margin: "6px 0 0" }}>
              {auditIntegrity.problems.map((p, i) => (
                <li key={i}>
                  {p.line}번째 줄 [{p.kind}] {p.detail}
                </li>
              ))}
            </ul>
          </span>
        )}
      </section>
      <section>
        <h2>인젝션 탐지 결과</h2>
        {injectionChecks.length === 0 ? (
          <p>아직 없음</p>
        ) : (
          <ul>
            {injectionChecks.map((c) => (
              <li key={c.id} style={{ color: c.isInjection ? "#d32f2f" : "#2e7d32" }}>
                {c.isInjection ? "[위험]" : "[안전]"} — {c.toolName} (score={c.score.toFixed(4)})
              </li>
            ))}
          </ul>
        )}
      </section>
      <ApprovalQueue approvals={approvals} onDecide={handleDecide} />
      <SanitizationCompareView sanitization={sanitization} />
      <ForensicReplay snapshots={snapshots} />
      {modalDecision && (
        <TrifectaApprovalModal
          decision={modalDecision}
          onActionClick={handleActionClick}
          onClose={() => setModalDecision(null)}
        />
      )}
    </div>
  );
}