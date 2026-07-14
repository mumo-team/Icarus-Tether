------------------------------ MODULE TaintLineage ------------------------------
(***************************************************************************)
(* Icarus-Tether policy-engine의 "값 단위 taint 전파 + 비대칭 정화"        *)
(* 핵심 안전 속성 모델.                                                    *)
(*                                                                         *)
(* 실제 코드 대응: policy-engine/src/lineage.ts (createTaintNode,          *)
(* declassifyNodeTag), policy-engine/src/index.ts (computeLineageDecision, *)
(* judgmentMode = "lineage").                                              *)
(*                                                                         *)
(* 증명 목표 (SinkSafety):                                                 *)
(*   어떤 실행으로도, SENSITIVE와 UNTRUSTED를 둘 다 가진 노드가            *)
(*   (정화되지 않은 채) sink에 도달하는 것은 불가능하다.                   *)
(*                                                                         *)
(* 모델링 원칙 — 과근사(over-approximation):                               *)
(*   실제 3층 parent 연결(MCP_REF / VALUE_MATCH / TEMPORAL_FALLBACK)이     *)
(*   어떤 부모를 고르든 "기존 노드의 임의 부분집합"의 한 경우다.           *)
(*   모델은 부모 선택(ps)과 자체 태그(own)를 비결정적으로 고르므로         *)
(*   실제 로직이 만들 수 있는 모든 계보를 포함한다. 따라서 이 모델에서     *)
(*   안전하면, 실제 연결 로직의 어떤 결과에서도 안전하다.                  *)
(*   (argTags도 own에 흡수된다 — 인자에 실려온 태그는 그 값 노드의 태그)   *)
(***************************************************************************)
EXTENDS FiniteSets

CONSTANT Nodes    \* 계보 노드의 유한 집합 (TLC가 전수 탐색 가능하게 3~4개)

Tags == {"SENSITIVE", "UNTRUSTED"}

\* lethal trifecta: 민감 + 비신뢰가 한 값에 겹침 (SinkClass는 ReachSink 전이 자체가 표현)
Trifecta(T) == Tags \subseteq T

VARIABLES
    created,     \* 생성된 노드 집합                  <-> lineageStore에 존재하는 노드
    tags,        \* [Nodes -> SUBSET Tags] 유효 태그  <-> TaintNode.tags
    parents,     \* [Nodes -> SUBSET Nodes]           <-> TaintNode.parents (생성 후 불변 = 소급 금지)
    exfiltrated  \* sink 통과 기록 + 통과 "시점"의 태그 스냅샷
                 \* (통과 후 정화로 tags가 줄어도 나간 시점의 안전성을 정직하게 판정하기 위함)

vars == <<created, tags, parents, exfiltrated>>

Init ==
    /\ created = {}
    /\ tags = [n \in Nodes |-> {}]
    /\ parents = [n \in Nodes |-> {}]
    /\ exfiltrated = {}

(***************************************************************************)
(* CreateNode  <->  lineage.ts createTaintNode                             *)
(*                                                                         *)
(* - ps \subseteq created: 부모는 이미 존재하는 노드만. 코드에서 parents는 *)
(*   항상 먼저 생성된 노드다 → 그래프가 구성상 DAG, 사이클·역류 원천 불가. *)
(* - tags' 합집합: effectiveTags = ownTags ∪ (모든 parent의 tags) — 전파.  *)
(*   오염은 이 전이에서만, 부모→자식 방향으로만 흐른다 (불변식 1: 단방향). *)
(* - own, ps의 비결정 선택 = 3층 연결 로직의 과근사 (모듈 헤더 참고).      *)
(***************************************************************************)
CreateNode(n, own, ps) ==
    /\ n \notin created
    /\ ps \subseteq created
    /\ created' = created \cup {n}
    /\ parents' = [parents EXCEPT ![n] = ps]
    /\ tags' = [tags EXCEPT ![n] = own \cup UNION {tags[p] : p \in ps}]
    /\ UNCHANGED exfiltrated

(***************************************************************************)
(* Declassify  <->  lineage.ts declassifyNodeTag                           *)
(*                                                                         *)
(* - tags[n]에서 t 하나만 제거. 이 액션에 자식을 갱신하는 항이 아예 없다   *)
(*   — 코드에 자손 순회가 없는 것과 정확히 대응 (불변식 2: 비대칭.         *)
(*   부모 정화가 자식 태그를 자동으로 떼지 않는다 — 자식은 각자 정화).     *)
(* - parents는 UNCHANGED — 계보는 역사, 소급 수정 금지 (불변식 3).         *)
(* - 코드에서 이 함수는 attemptSanitization(검증 통과 시)만 호출하지만,    *)
(*   모델은 "언제든 어떤 노드든 정화될 수 있다"로 과근사 — 검증 로직의     *)
(*   구현이 무엇이든 정화 순서와 무관하게 안전함을 보인다.                 *)
(***************************************************************************)
Declassify(n, t) ==
    /\ n \in created
    /\ t \in tags[n]
    /\ tags' = [tags EXCEPT ![n] = @ \ {t}]
    /\ UNCHANGED <<created, parents, exfiltrated>>

(***************************************************************************)
(* ReachSink  <->  index.ts computeLineageDecision (judgmentMode="lineage")*)
(*                                                                         *)
(* - guard ~Trifecta(tags[n]): 차단 규칙 그 자체. 트라이펙타 노드는 이     *)
(*   전이가 비활성 = evaluateToolCall이 allowed:false를 반환해 sink로      *)
(*   나가지 못한다. (OUTBOUND_SINK 분류는 이 전이의 존재 자체가 표현 —     *)
(*   READ 도구는 sink가 아니므로 모델링 대상이 아님)                       *)
(* - 노드당 1회만 통과(둘째 guard): 상태 공간 축소용 단순화.               *)
(*   정당화: 생성 이후 tags는 절대 늘지 않으므로(늘리는 전이가 없음),      *)
(*   재통과 시점의 태그는 항상 첫 통과 이하 — 새로운 위반을 만들 수 없다.  *)
(* - tagsAtExit 스냅샷: 통과 "시점"의 태그를 기록해 사후 정화가 판정을     *)
(*   소급 왜곡하지 못하게 한다.                                            *)
(***************************************************************************)
ReachSink(n) ==
    /\ n \in created
    /\ \A e \in exfiltrated : e.node # n
    /\ ~Trifecta(tags[n])
    /\ exfiltrated' = exfiltrated \cup {[node |-> n, tagsAtExit |-> tags[n]]}
    /\ UNCHANGED <<created, tags, parents>>

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
    /\ \A e \in exfiltrated : e.node \in created /\ e.tagsAtExit \subseteq Tags

\* ★ 핵심 안전 속성: 트라이펙타 값은 어떤 실행 순서로도 sink를 통과하지 못한다.
\*   "정화되지 않은 채"가 자동으로 반영됨 — 정화된 노드는 그 시점 tags에서
\*   태그가 빠져 있으므로 Trifecta가 거짓이 되어 통과가 허용되는 게 맞다.
SinkSafety == \A e \in exfiltrated : ~Trifecta(e.tagsAtExit)

\* 구조 불변식: 부모는 항상 자기보다 먼저 생성된 다른 노드 (DAG — 역류·사이클 불가)
ParentsExist == \A n \in created : parents[n] \subseteq created \ {n}

\* 미생성 노드는 태그도 부모도 없다 (상태 위생)
Unborn == \A n \in Nodes \ created : tags[n] = {} /\ parents[n] = {}

==================================================================================
