------------------------------ MODULE TaintLineage ------------------------------
(***************************************************************************)
(* Icarus-Tether policy-engine의 "값 단위 taint 전파 + 비대칭 정화 +        *)
(* ★비신뢰 노출이력(monotone)" 핵심 안전 속성 모델.                        *)
(*                                                                         *)
(* 실제 코드 대응: policy-engine/src/lineage.ts (createTaintNode,          *)
(* declassifyNodeTag), policy-engine/src/index.ts (computeLineageDecision, *)
(* judgmentMode = "lineage").                                              *)
(*                                                                         *)
(* ★ F1 수정 반영판 (헌팅에서 발견한 정화 세탁 미탐):                       *)
(*   이전 모델은 U를 S와 대칭인 노드 태그로 두고 Declassify로 제거 가능하게 *)
(*   했다 — 이는 정확히 F1의 형식적 뿌리였다: "정화가 U를 떼면 세션 U축이   *)
(*   꺼진다". 실제 코드의 비대칭 위협 모델은 U축을 "세션 존재"로 보는데,    *)
(*   그 세션 존재를 정화가 꺼버려(C1/P6) 정화와 무관한 유출·삭제가 열렸다.  *)
(*                                                                         *)
(*   수정: U축을 노드 태그가 아니라 **세션 노출이력(exposure)**으로 모델링.  *)
(*   - exposure: 어떤 노드든 U를 획득하면 TRUE, 이후 절대 FALSE 안 됨       *)
(*     (grow-only). Declassify는 노드의 S 태그(값-계보)만 떼고 exposure는   *)
(*     건드리지 않는다 — "정화는 그 값을 안전하게 만들 뿐, 세션이 비신뢰에  *)
(*     노출됐던 사실은 못 되돌린다".                                        *)
(*   - 차단 규칙: valueSensitive(노드가 S를 실제로 담음) AND exposure.       *)
(*     → S 토큰화로 노드 S가 빠지면 통과(RE35), U-only는 S가 없어 통과       *)
(*       (RE36), "U 정화 후 무관 S 전송"(C1)만 차단.                        *)
(*                                                                         *)
(* 증명 목표 (ExfilSafety):                                                *)
(*   어떤 실행으로도, 세션이 비신뢰에 노출된 상태에서 민감(S) 값이 sink에   *)
(*   도달하는 것은 불가능하다. (정화로 U 노드를 떼도 exposure가 살아 차단)   *)
(*                                                                         *)
(* 양립 논증 (세탁방지 vs 과차단방지가 서로 다른 축이라 안 충돌):            *)
(*   - 세탁 방지: exposure가 monotone이라 정화가 U축을 못 끈다.             *)
(*   - 과차단 방지: 차단이 valueSensitive AND exposure라, S를 정화(값-계보  *)
(*     에서 제거)하면 여전히 통과한다. 두 목표가 각각 다른 연산자 항에 걸림. *)
(*                                                                         *)
(* 모델링 원칙 — 과근사(over-approximation):                               *)
(*   부모 선택(ps)·자체 태그(own) 비결정 = 3층 연결 로직의 모든 결과 포함.  *)
(***************************************************************************)
EXTENDS FiniteSets

CONSTANT Nodes    \* 계보 노드의 유한 집합 (TLC가 전수 탐색 가능하게 3~4개)

Tags == {"SENSITIVE", "UNTRUSTED"}

VARIABLES
    created,     \* 생성된 노드 집합                  <-> lineageStore에 존재하는 노드
    tags,        \* [Nodes -> SUBSET Tags] 유효 태그  <-> TaintNode.tags (값-계보)
    parents,     \* [Nodes -> SUBSET Nodes]           <-> TaintNode.parents (생성 후 불변)
    exposure,    \* BOOLEAN 세션 비신뢰 노출이력       <-> ★ untrustedExposure (grow-only)
    exfiltrated  \* sink 통과 기록 + 통과 "시점"의 (S여부, exposure) 스냅샷

vars == <<created, tags, parents, exposure, exfiltrated>>

Init ==
    /\ created = {}
    /\ tags = [n \in Nodes |-> {}]
    /\ parents = [n \in Nodes |-> {}]
    /\ exposure = FALSE
    /\ exfiltrated = {}

(***************************************************************************)
(* CreateNode  <->  lineage.ts createTaintNode + index.ts 태깅.            *)
(*                                                                         *)
(* - tags' 합집합: effectiveTags = own ∪ (모든 parent tags) — 값-계보 전파. *)
(* - ★ exposure' : 이 노드가 (자체·상속으로) U를 지니면 세션 노출이력 ON.   *)
(*   한 번 켜지면 이후 어떤 전이도 끄지 않는다 (monotone) — 코드에서 U 태그 *)
(*   가 생기는 recordToolResult 경로가 exposure 플래그를 세우는 것과 대응.  *)
(***************************************************************************)
CreateNode(n, own, ps) ==
    /\ n \notin created
    /\ ps \subseteq created
    /\ created' = created \cup {n}
    /\ parents' = [parents EXCEPT ![n] = ps]
    /\ LET newTags == own \cup UNION {tags[p] : p \in ps}
       IN /\ tags' = [tags EXCEPT ![n] = newTags]
          /\ exposure' = (exposure \/ ("UNTRUSTED" \in newTags))
    /\ UNCHANGED exfiltrated

(***************************************************************************)
(* Declassify  <->  lineage.ts declassifyNodeTag (attemptSanitization).    *)
(*                                                                         *)
(* - tags[n]에서 t 하나만 제거 (값-계보). 자손 순회 없음 (비대칭).          *)
(* - ★ exposure UNCHANGED — 이것이 F1 수정의 핵심. 정화는 노드의 값-계보    *)
(*   태그(S/U)만 떼고, 세션 노출이력은 절대 되돌리지 않는다. U 노드를 정화  *)
(*   해도 exposure가 살아 있어 이후 S 유출이 차단된다 (C1 세탁 방지).       *)
(*   (이전 모델은 여기서 U를 떼면 트라이펙타가 풀려 세탁이 가능했다.)       *)
(***************************************************************************)
Declassify(n, t) ==
    /\ n \in created
    /\ t \in tags[n]
    /\ tags' = [tags EXCEPT ![n] = @ \ {t}]
    /\ UNCHANGED <<created, parents, exposure, exfiltrated>>

(***************************************************************************)
(* ReachSink  <->  index.ts computeLineageDecision (비대칭 + 노출이력).     *)
(*                                                                         *)
(* - guard ~(SENSITIVE ∈ tags[n] ∧ exposure): 차단 규칙.                    *)
(*   valueSensitive(이 값이 실제로 민감을 담음 = 값-계보 S) AND             *)
(*   exposure(세션이 비신뢰에 노출됨). 트라이펙타의 비대칭 판정 그 자체.    *)
(* - ★ 1회 통과 단순화 제거: exposure가 monotone하게 늘 수 있으므로         *)
(*   (S만 담은 값이 노출 전 통과 → 이후 노출 → 재통과 시 차단돼야 함),      *)
(*   각 통과를 독립 판정한다. 통과 시점의 (S여부, exposure) 스냅샷을 기록.   *)
(*   재통과가 같은 스냅샷이면 집합에서 dedupe되어 상태는 유한하다.          *)
(***************************************************************************)
ReachSink(n) ==
    /\ n \in created
    /\ ~("SENSITIVE" \in tags[n] /\ exposure)
    /\ exfiltrated' = exfiltrated \cup
         {[node |-> n, sAtExit |-> "SENSITIVE" \in tags[n], exposureAtExit |-> exposure]}
    /\ UNCHANGED <<created, tags, parents, exposure>>

Next ==
    \/ \E n \in Nodes : \E own \in SUBSET Tags : \E ps \in SUBSET created :
           CreateNode(n, own, ps)
    \/ \E n \in Nodes, t \in Tags : Declassify(n, t)
    \/ \E n \in Nodes : ReachSink(n)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* 불변식                                                                  *)
(***************************************************************************)

TypeOK ==
    /\ created \subseteq Nodes
    /\ tags \in [Nodes -> SUBSET Tags]
    /\ parents \in [Nodes -> SUBSET Nodes]
    /\ exposure \in BOOLEAN
    /\ \A e \in exfiltrated :
         /\ e.node \in created
         /\ e.sAtExit \in BOOLEAN
         /\ e.exposureAtExit \in BOOLEAN

\* ★ 핵심 안전 속성 (F1 세탁 방지): 세션이 비신뢰에 노출된 상태에서 민감 값이
\*   sink를 통과하는 일은 없다. 정화로 U 노드를 떼도 exposure가 살아 있어,
\*   "U 정화 후 무관 S 전송"(C1)이 차단된다. 통과 "시점" 스냅샷으로 판정하므로
\*   사후 정화가 판정을 소급 왜곡하지 못한다.
ExfilSafety == \A e \in exfiltrated : ~(e.sAtExit /\ e.exposureAtExit)

\* ★ 노출이력 단조성: exposure는 한 번 TRUE가 되면 절대 FALSE로 돌아가지 않는다
\*   (정화·통과·생성 어느 전이도 끄지 못함). 세탁 방지의 형식적 근거.
ExposureMonotone == [][exposure => exposure']_vars

\* 구조 불변식: 부모는 항상 자기보다 먼저 생성된 다른 노드 (DAG — 역류·사이클 불가)
ParentsExist == \A n \in created : parents[n] \subseteq created \ {n}

\* 미생성 노드는 태그도 부모도 없다 (상태 위생)
Unborn == \A n \in Nodes \ created : tags[n] = {} /\ parents[n] = {}

\* ── 비공허성 witness용 (본 cfg에는 넣지 않는다 — 스크래치 cfg에서 반례=정상동작) ──
\* NoCleanSExit 반례 = 노출 전 민감값이 정상 통과한다 (과차단 아님 — RE35류).
NoCleanSExit == \A e \in exfiltrated : ~e.sAtExit
\* NoUonlyExit 반례 = U 정화 후 S 없는 값이 통과한다 (RE36류).
NoExposedExit == \A e \in exfiltrated : ~e.exposureAtExit

==================================================================================
