------------------------------- MODULE TaintHITL -------------------------------
(***************************************************************************)
(* HITL(사람 승인 오버라이드) 모델 — 승인 재검증 누락(TOCTOU) 재현용.      *)
(*                                                                         *)
(* 실제 코드 대응: policy-engine/src/hitl.ts(evaluateOverridability /      *)
(* offerOverride / resolveApproval / consumeApprovalIfMatching)과          *)
(* index.ts computeLineageDecision의 HITL 통합부(소비→차단→제안 순서).     *)
(*                                                                         *)
(* ★ 이 모델은 "지금 코드"를 그대로 옮긴다 — ConsumeSink에 소비 시점       *)
(* weak 재확인 guard가 의도적으로 없다(consumeApprovalIfMatching이 지문    *)
(* 일치+APPROVED+미사용만 보는 코드 그대로). 따라서 HITLSafety 불변식은    *)
(* 이 모델에서 "깨져야 정상"이다: TLC의 반례가 곧 TOCTOU의 형식적 증거.    *)
(* 예상 최단 반례: Create(weak 트라이펙타) → Offer → Approve →             *)
(* Escalate(weak→strong) → ConsumeSink(재확인 없이 통과) → 위반.           *)
(*                                                                         *)
(* 단순화 (기존 모델과의 관계):                                            *)
(*  - 호출 ↔ 노드 1:1: "노드 n의 값을 내보내는 sink 호출"을 호출 n으로     *)
(*    식별한다. 승인 지문 sha256(sessionId|toolName|args)이 args만 고정할  *)
(*    뿐 계보 상태를 인코딩하지 않는다는 성질이, "노드 식별자는 고정인데   *)
(*    strength는 변한다"로 표현된다 — 이 어긋남이 TOCTOU의 몸통.           *)
(*  - evidence를 단일 노드로 접음: evaluateOverridability는 "오염 실은     *)
(*    노드가 전부 weak"이므로 단일 노드에선 strength[n]="weak"로 환원.     *)
(*  - parents/cascade/Declassify 제외: 전파·정화 안전성은                  *)
(*    TaintLineage(Live).tla가 이미 증명한 직교 축.                        *)
(***************************************************************************)
EXTENDS FiniteSets

CONSTANT Nodes    \* 유한 노드 집합 (상태 폭발 관리를 위해 기본 3개)

Tags == {"SENSITIVE", "UNTRUSTED"}

Trifecta(T) == Tags \subseteq T

\* previewParentLinks가 판정 때마다 재계산하는 연결 신뢰도(link.weak).
\* MCP_REF=strong, TEMPORAL_FALLBACK=weak, VALUE_MATCH=토큰 강도로 결정 (lineage.ts)
Strengths == {"weak", "strong"}

\* hitl.ts offers Map의 상태. PENDING은 OFFERED에 접는다 — requestApproval
\* (OFFERED→PENDING)은 오염 흐름에 아무 영향 없는 부기 전이(대기 등록)라
\* 안전성 관점에서 상태를 늘릴 이유가 없다.
HitlStatus == {"NONE", "OFFERED", "APPROVED", "REJECTED", "USED"}

VARIABLES
    created,     \* 생성된 노드 집합                    <-> lineageStore
    tags,        \* [Nodes -> SUBSET Tags]              <-> TaintNode.tags
    strength,    \* [Nodes -> Strengths] 연결 신뢰도    <-> previewParentLinks의 link.weak (매 판정 재계산 = 가변)
    hitl,        \* [Nodes -> HitlStatus] 승인 상태     <-> hitl.ts offers Map (지문 키)
    exfiltrated  \* {[node, tagsAtExit, strengthAtExit, via]} — 통과 "시점" 스냅샷

vars == <<created, tags, strength, hitl, exfiltrated>>

Init ==
    /\ created = {}
    /\ tags = [n \in Nodes |-> {}]
    /\ strength = [n \in Nodes |-> "weak"]
    /\ hitl = [n \in Nodes |-> "NONE"]
    /\ exfiltrated = {}

(***************************************************************************)
(* CreateNode  <->  recordToolResult/createTaintNode + resolveParents의    *)
(* 연결 분류. own(태그)·st(연결 신뢰도) 비결정 선택 = 기존 모델과 같은     *)
(* 과근사: 실제 로직이 어떤 태그·분류를 내놓든 모델의 한 경우.             *)
(***************************************************************************)
CreateNode(n, own, st) ==
    /\ n \notin created
    /\ created' = created \cup {n}
    /\ tags' = [tags EXCEPT ![n] = own]
    /\ strength' = [strength EXCEPT ![n] = st]
    /\ UNCHANGED <<hitl, exfiltrated>>

(***************************************************************************)
(* AddTag  <->  lineage.ts addNodeTags (사후 태그 추가).                   *)
(* 제안~소비 사이 태그 변동 인터리빙도 탐색되도록 포함 (cascade는 parents  *)
(* 를 접었으므로 없음 — 하향 전파는 TaintLineageLive.tla가 증명).          *)
(***************************************************************************)
AddTag(n, t) ==
    /\ n \in created
    /\ t \notin tags[n]
    /\ tags' = [tags EXCEPT ![n] = @ \cup {t}]
    /\ UNCHANGED <<created, strength, hitl, exfiltrated>>

(***************************************************************************)
(* Offer  <->  computeLineageDecision의 차단 분기(index.ts:396-401):       *)
(* evaluateOverridability(hitl.ts:41)=true일 때만 offerOverride.           *)
(* guard의 strength="weak"가 곧 evaluateOverridability — "오염을 실은      *)
(* 노드가 전부 weak 연결"의 단일 노드 환원. Trifecta guard는 제안이        *)
(* 차단(트라이펙타) 시점에만 일어나는 코드 구조.                           *)
(* REJECTED/USED 후 재제안 허용 = offerOverride가 진행 중(OFFERED/PENDING) *)
(* 제안이 없으면 새 제안을 만드는 것과 대응 (approvalId 갱신은 추상화).    *)
(***************************************************************************)
Offer(n) ==
    /\ n \in created
    /\ Trifecta(tags[n])
    /\ strength[n] = "weak"
    /\ hitl[n] \in {"NONE", "REJECTED", "USED"}
    /\ hitl' = [hitl EXCEPT ![n] = "OFFERED"]
    /\ UNCHANGED <<created, tags, strength, exfiltrated>>

(***************************************************************************)
(* Approve/Reject  <->  requestApproval(PENDING 등록, 접음) +              *)
(* resolveApproval(approved=true|false) (hitl.ts:161).                     *)
(* 사람의 결정은 모델 입장에선 비결정 — 언제 어느 쪽으로든 날 수 있다.     *)
(***************************************************************************)
Approve(n) ==
    /\ hitl[n] = "OFFERED"
    /\ hitl' = [hitl EXCEPT ![n] = "APPROVED"]
    /\ UNCHANGED <<created, tags, strength, exfiltrated>>

Reject(n) ==
    /\ hitl[n] = "OFFERED"
    /\ hitl' = [hitl EXCEPT ![n] = "REJECTED"]
    /\ UNCHANGED <<created, tags, strength, exfiltrated>>

(***************************************************************************)
(* ★ Escalate — TOCTOU의 심장. 승인과 소비 "사이"에 끼어들 수 있는 전이.  *)
(*                                                                         *)
(* <-> 승인 후 recordToolResult로 새 노드가 생겨, previewParentLinks가     *)
(* 같은 args를 strong으로 재분류하는 상황(긴 토큰 VALUE_MATCH 또는         *)
(* MCP_REF, lineage.ts:256-276). 지문은 args만 고정하므로 승인은 그대로    *)
(* 유효한데 연결 신뢰도만 바뀐다 — "그때는 몰랐던 미래 정보"의 유입.       *)
(*                                                                         *)
(* hitl 상태에 guard가 없다 = 어느 시점에든(APPROVED 이후 포함) 발생       *)
(* 가능. weak→strong 단조 — 반대 방향(strong→weak 느슨화)은 별개 관심사라  *)
(* 두지 않는다.                                                            *)
(***************************************************************************)
Escalate(n) ==
    /\ n \in created
    /\ strength[n] = "weak"
    /\ strength' = [strength EXCEPT ![n] = "strong"]
    /\ UNCHANGED <<created, tags, hitl, exfiltrated>>

(***************************************************************************)
(* ★ ConsumeSink  <->  consumeApprovalIfMatching(hitl.ts:184) + index.ts   *)
(* 364-375의 소비 분기: 트라이펙타 차단 분기에 들어가자마자 지문 일치 +    *)
(* APPROVED + 미사용이면 1회 소비하고 통과.                                *)
(*                                                                         *)
(* ★★ guard에 strength[n]="weak" 재확인이 "의도적으로 없다" — 지금 코드가  *)
(* 소비 직전에 evaluateOverridability를 재호출하지 않는 버그를 그대로      *)
(* 모델링한 것. 이 줄이 없어서 HITLSafety 반례가 나오면, 그것이 곧         *)
(* "형식검증이 실제 TOCTOU를 발견했다"는 증거다.                           *)
(*                                                                         *)
(* Trifecta는 guard에 있다 — 소비가 트라이펙타 차단 분기 "안"에서만        *)
(* 일어나는 코드 구조(index.ts:355-364). 즉 태그는 소비 시점에 재확인되지  *)
(* 만 연결 신뢰도(weak)는 재확인되지 않는다 — 비대칭이 곧 구멍.            *)
(* hitl'="USED" = offer.used=true (single-use).                            *)
(***************************************************************************)
ConsumeSink(n) ==
    /\ n \in created
    /\ Trifecta(tags[n])
    /\ hitl[n] = "APPROVED"
    /\ hitl' = [hitl EXCEPT ![n] = "USED"]
    /\ exfiltrated' = exfiltrated \cup
         {[node |-> n, tagsAtExit |-> tags[n],
           strengthAtExit |-> strength[n], via |-> "OVERRIDE"]}
    /\ UNCHANGED <<created, tags, strength>>

(***************************************************************************)
(* ReachSinkClean  <->  computeLineageDecision의 정상 통과 경로            *)
(* (트라이펙타 아님 → allowed). 통과 시점 스냅샷 기록은 Live 모델 관례.    *)
(***************************************************************************)
ReachSinkClean(n) ==
    /\ n \in created
    /\ ~Trifecta(tags[n])
    /\ exfiltrated' = exfiltrated \cup
         {[node |-> n, tagsAtExit |-> tags[n],
           strengthAtExit |-> strength[n], via |-> "CLEAN"]}
    /\ UNCHANGED <<created, tags, strength, hitl>>

Next ==
    \/ \E n \in Nodes : \E own \in SUBSET Tags : \E st \in Strengths :
           CreateNode(n, own, st)
    \/ \E n \in Nodes, t \in Tags : AddTag(n, t)
    \/ \E n \in Nodes : Offer(n)
    \/ \E n \in Nodes : Approve(n)
    \/ \E n \in Nodes : Reject(n)
    \/ \E n \in Nodes : Escalate(n)
    \/ \E n \in Nodes : ConsumeSink(n)
    \/ \E n \in Nodes : ReachSinkClean(n)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* 불변식                                                                  *)
(***************************************************************************)

TypeOK ==
    /\ created \subseteq Nodes
    /\ tags \in [Nodes -> SUBSET Tags]
    /\ strength \in [Nodes -> Strengths]
    /\ hitl \in [Nodes -> HitlStatus]
    /\ \A e \in exfiltrated :
         /\ e.node \in created
         /\ e.tagsAtExit \subseteq Tags
         /\ e.strengthAtExit \in Strengths
         /\ e.via \in {"CLEAN", "OVERRIDE"}

\* ★ 핵심 안전 속성: strong 연결로 오염을 실은 트라이펙타는 어떤 승인으로도
\*   sink에 도달할 수 없어야 한다 (strong = 사람도 못 여는 확정 차단이어야 함).
\*   이 모델(= 지금 코드)에서는 깨진다 — 반례가 TOCTOU의 형식적 증거.
\*
\*   반례는 구조적으로 반드시 Offer→Approve→Escalate→ConsumeSink 순서를 포함한다:
\*   (1) strong 트라이펙타 유출은 ConsumeSink로만 가능(ReachSinkClean은 ¬Trifecta),
\*   (2) ConsumeSink는 APPROVED 필요 → Approve → Offer 필요,
\*   (3) Offer는 strength="weak" guard → 제안 시점엔 weak였고,
\*   (4) strength 변경은 Escalate뿐(단조) → 소비 시점 strong이려면 Offer 이후
\*       Escalate가 반드시 개입. 즉 다른 경로의 위반은 표현 자체가 불가능.
HITLSafety ==
    \A e \in exfiltrated :
        Trifecta(e.tagsAtExit) => e.strengthAtExit = "weak"

\* 보조(비공허성): 트라이펙타의 유일한 탈출구는 HITL 오버라이드다 —
\* 기본 차단 guard가 실제로 일하고 있음을 확인 (CLEAN 경로로는 절대 못 나감).
TrifectaExitOnlyViaOverride ==
    \A e \in exfiltrated :
        Trifecta(e.tagsAtExit) => e.via = "OVERRIDE"

\* 미생성 노드는 태그·연결·승인 상태가 없다 (전이들이 created 밖으로 새지 않음)
Unborn ==
    \A n \in Nodes \ created :
        tags[n] = {} /\ strength[n] = "weak" /\ hitl[n] = "NONE"

=================================================================================
