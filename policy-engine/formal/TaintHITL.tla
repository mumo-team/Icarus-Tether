------------------------------- MODULE TaintHITL -------------------------------
(***************************************************************************)
(* HITL(사람 승인 오버라이드) 모델 — 승인 재검증 누락(TOCTOU) 재현용.      *)
(*                                                                         *)
(* 실제 코드 대응: policy-engine/src/hitl.ts(evaluateOverridability /      *)
(* offerOverride / resolveApproval / consumeApprovalIfMatching)과          *)
(* index.ts computeLineageDecision의 HITL 통합부(소비→차단→제안 순서).     *)
(*                                                                         *)
(* ★ 2단계(수정 후): 1단계 모델은 소비 시점 재확인이 없는 "버그 그대로"    *)
(* 였고 TLC가 HITLSafety 위반 반례(Offer→Approve→Escalate→Consume, 5스텝) *)
(* 를 내놓았다 (git 이력 참조). 이 버전은 수정된 코드를 옮긴 것이다:       *)
(* Offer가 제안 시점 계보 지문(snap)을 저장하고, ConsumeSink는 현재 상태가 *)
(* snap과 일치할 때만 통과(consumeApprovalIfMatching의 lineageFingerprint  *)
(* 대조). 불일치면 ConsumeStale이 승인을 영구 무효화(used=true)하고 차단을 *)
(* 유지한다. 이제 HITLSafety는 전 상태 탐색에서 위반 0이어야 한다.         *)
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
    snap,        \* [Nodes -> {"none"} ∪ Strengths]     <-> ★offer.lineageFingerprint (제안 시점 계보 지문)
    exfiltrated  \* {[node, tagsAtExit, strengthAtExit, via]} — 통과 "시점" 스냅샷

vars == <<created, tags, strength, hitl, snap, exfiltrated>>

Init ==
    /\ created = {}
    /\ tags = [n \in Nodes |-> {}]
    /\ strength = [n \in Nodes |-> "weak"]
    /\ hitl = [n \in Nodes |-> "NONE"]
    /\ snap = [n \in Nodes |-> "none"]
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
    /\ UNCHANGED <<hitl, snap, exfiltrated>>

(***************************************************************************)
(* AddTag  <->  lineage.ts addNodeTags (사후 태그 추가).                   *)
(* 제안~소비 사이 태그 변동 인터리빙도 탐색되도록 포함 (cascade는 parents  *)
(* 를 접었으므로 없음 — 하향 전파는 TaintLineageLive.tla가 증명).          *)
(***************************************************************************)
AddTag(n, t) ==
    /\ n \in created
    /\ t \notin tags[n]
    /\ tags' = [tags EXCEPT ![n] = @ \cup {t}]
    /\ UNCHANGED <<created, strength, hitl, snap, exfiltrated>>

(***************************************************************************)
(* Offer  <->  computeLineageDecision의 차단 분기(index.ts:396-401):       *)
(* evaluateOverridability(hitl.ts:41)=true일 때만 offerOverride.           *)
(* guard의 strength="weak"가 곧 evaluateOverridability — "오염을 실은      *)
(* 노드가 전부 weak 연결"의 단일 노드 환원. Trifecta guard는 제안이        *)
(* 차단(트라이펙타) 시점에만 일어나는 코드 구조.                           *)
(* REJECTED/USED 후 재제안 허용 = offerOverride가 진행 중(OFFERED/PENDING) *)
(* 제안이 없으면 새 제안을 만드는 것과 대응 (approvalId 갱신은 추상화).    *)
(*                                                                         *)
(* ★수정: snap' = strength[n] — offer.lineageFingerprint 저장(제안 시점    *)
(* 계보 지문). guard가 weak이므로 snap은 항상 "weak"로 기록되지만, 코드의  *)
(* "지문 저장 → 소비 시 대조" 형태를 1:1로 유지하기 위해 대입으로 쓴다.    *)
(* 코드의 SUPERSEDED(OFFERED 중 계보 변화 → 새 제안 대체)는 이 상태공간에  *)
(* 선 비활성 — 제안 자격이 weak뿐이고 태그는 offer 시점에 이미 가득({S,U}) *)
(* 이라 "제안 가능한 두 시점 사이"에 지문이 달라질 수 없다 (환원 주석 참조).*)
(***************************************************************************)
Offer(n) ==
    /\ n \in created
    /\ Trifecta(tags[n])
    /\ strength[n] = "weak"
    /\ hitl[n] \in {"NONE", "REJECTED", "USED"}
    /\ hitl' = [hitl EXCEPT ![n] = "OFFERED"]
    /\ snap' = [snap EXCEPT ![n] = strength[n]]
    /\ UNCHANGED <<created, tags, strength, exfiltrated>>

(***************************************************************************)
(* Approve/Reject  <->  requestApproval(PENDING 등록, 접음) +              *)
(* resolveApproval(approved=true|false) (hitl.ts:161).                     *)
(* 사람의 결정은 모델 입장에선 비결정 — 언제 어느 쪽으로든 날 수 있다.     *)
(***************************************************************************)
Approve(n) ==
    /\ hitl[n] = "OFFERED"
    /\ hitl' = [hitl EXCEPT ![n] = "APPROVED"]
    /\ UNCHANGED <<created, tags, strength, snap, exfiltrated>>

Reject(n) ==
    /\ hitl[n] = "OFFERED"
    /\ hitl' = [hitl EXCEPT ![n] = "REJECTED"]
    /\ UNCHANGED <<created, tags, strength, snap, exfiltrated>>

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
    /\ UNCHANGED <<created, tags, hitl, snap, exfiltrated>>

(***************************************************************************)
(* ★ ConsumeSink  <->  consumeApprovalIfMatching(hitl.ts) + index.ts의     *)
(* 소비 분기: 트라이펙타 차단 분기에 들어가자마자 지문 일치 + APPROVED +   *)
(* 미사용 + ★계보 지문 일치면 1회 소비하고 통과.                           *)
(*                                                                         *)
(* ★★ 수정된 guard: strength[n] = snap[n] — 1단계에서 의도적으로 뺐던      *)
(* 재검증. 코드의 offer.lineageFingerprint === 현재 지문 대조와 1:1.       *)
(* Offer guard가 weak이므로 snap="weak" — 일치 ⇔ 소비 시점에도 weak ⇔      *)
(* 승인 시점과 계보 상태가 그대로. 이 한 줄이 1단계 반례                   *)
(* (Offer→Approve→Escalate→Consume)의 마지막 스텝을 비활성화한다.          *)
(*                                                                         *)
(* Trifecta는 guard에 있다 — 소비가 트라이펙타 차단 분기 "안"에서만        *)
(* 일어나는 코드 구조. hitl'="USED" = offer.used=true (single-use).        *)
(***************************************************************************)
ConsumeSink(n) ==
    /\ n \in created
    /\ Trifecta(tags[n])
    /\ hitl[n] = "APPROVED"
    /\ strength[n] = snap[n]    \* ★TOCTOU 재검증 — 계보 지문 대조
    /\ hitl' = [hitl EXCEPT ![n] = "USED"]
    /\ exfiltrated' = exfiltrated \cup
         {[node |-> n, tagsAtExit |-> tags[n],
           strengthAtExit |-> strength[n], via |-> "OVERRIDE"]}
    /\ UNCHANGED <<created, tags, strength, snap>>

(***************************************************************************)
(* ★ ConsumeStale  <->  consumeApprovalIfMatching의 불일치 분기: 계보      *)
(* 지문이 다르면 승인을 영구 무효화(used=true, audit OVERRIDE_STALE)하고   *)
(* null 반환 = 차단 유지(exfiltrated 불변 — 아무것도 안 나간다).           *)
(* 무효화 후에도 여전히 weak면 Offer가 USED에서 재제안 가능 — 재평가 시    *)
(* 새 제안 자동 발급과 대응. 이 전이 덕에 "낡은 승인이 남아 영원히         *)
(* 대기하는" 상태가 아니라 코드처럼 명시적으로 소거되는 수명주기가 된다.   *)
(***************************************************************************)
ConsumeStale(n) ==
    /\ n \in created
    /\ Trifecta(tags[n])
    /\ hitl[n] = "APPROVED"
    /\ strength[n] # snap[n]    \* 승인~소비 사이에 계보가 달라졌다
    /\ hitl' = [hitl EXCEPT ![n] = "USED"]
    /\ UNCHANGED <<created, tags, strength, snap, exfiltrated>>

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
    /\ UNCHANGED <<created, tags, strength, hitl, snap>>

Next ==
    \/ \E n \in Nodes : \E own \in SUBSET Tags : \E st \in Strengths :
           CreateNode(n, own, st)
    \/ \E n \in Nodes, t \in Tags : AddTag(n, t)
    \/ \E n \in Nodes : Offer(n)
    \/ \E n \in Nodes : Approve(n)
    \/ \E n \in Nodes : Reject(n)
    \/ \E n \in Nodes : Escalate(n)
    \/ \E n \in Nodes : ConsumeSink(n)
    \/ \E n \in Nodes : ConsumeStale(n)
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
    /\ snap \in [Nodes -> {"none"} \cup Strengths]
    /\ \A e \in exfiltrated :
         /\ e.node \in created
         /\ e.tagsAtExit \subseteq Tags
         /\ e.strengthAtExit \in Strengths
         /\ e.via \in {"CLEAN", "OVERRIDE"}

\* ★ 핵심 안전 속성: strong 연결로 오염을 실은 트라이펙타는 어떤 승인으로도
\*   sink에 도달할 수 없다 (strong = 사람도 못 여는 확정 차단).
\*   1단계(재검증 없는 모델)에선 5스텝 반례로 깨졌다. 수정 후 성립 논증:
\*   트라이펙타 유출은 ConsumeSink뿐이고, 그 guard가 strength[n]=snap[n]을
\*   요구하는데 snap은 Offer가 "weak"일 때만 기록되므로, 통과 시점 strength도
\*   반드시 "weak" — strengthAtExit="strong"인 트라이펙타 기록은 도달 불가능.
\*   (TLC 전 상태 탐색으로 확인 — 아래 환원 주석도 참조.)
\*
\*   ★환원 주석(정직성): 단일 노드 evidence + 태그 2종에선 offer 시점 태그가
\*   항상 {S,U}(가득)라 승인~소비 사이에 변할 수 있는 것이 strength뿐이다.
\*   따라서 코드의 지문 대조(방법 B: "계보 상태 그대로")는 이 상태공간에서
\*   "여전히 weak"(방법 A) 재확인과 동치로 접힌다. B가 A보다 엄격해지는 경우
\*   (변경됐지만 여전히 weak — 승인 이식)는 모델 밖이며, 코드 테스트
\*   (hitl.toctou.test.ts T3)가 커버한다.
HITLSafety ==
    \A e \in exfiltrated :
        Trifecta(e.tagsAtExit) => e.strengthAtExit = "weak"

\* 보조(비공허성): 트라이펙타의 유일한 탈출구는 HITL 오버라이드다 —
\* 기본 차단 guard가 실제로 일하고 있음을 확인 (CLEAN 경로로는 절대 못 나감).
TrifectaExitOnlyViaOverride ==
    \A e \in exfiltrated :
        Trifecta(e.tagsAtExit) => e.via = "OVERRIDE"

\* 미생성 노드는 태그·연결·승인 상태·지문이 없다 (전이들이 created 밖으로 새지 않음)
Unborn ==
    \A n \in Nodes \ created :
        tags[n] = {} /\ strength[n] = "weak" /\ hitl[n] = "NONE" /\ snap[n] = "none"

\* 승인 진행 중(OFFERED/APPROVED)이면 제안 시점 지문이 반드시 "weak"로 저장돼
\* 있다 — Offer의 weak guard와 snap 기록이 어긋나지 않음 (지문 저장의 건전성)
SnapConsistency ==
    \A n \in Nodes :
        hitl[n] \in {"OFFERED", "APPROVED"} => snap[n] = "weak"

=================================================================================
