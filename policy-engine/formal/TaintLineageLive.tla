---------------------------- MODULE TaintLineageLive ----------------------------
(***************************************************************************)
(* TaintLineage의 확장: live 전파(addNodeTags + cascadeDown)까지 포함.     *)
(*                                                                         *)
(* 실제 코드 대응: policy-engine/src/lineage.ts의 addNodeTags(사후 태그    *)
(* 추가)와 cascadeDown(자손 하향 전파, propagationMode="live"), 그리고     *)
(* 기존 모델과 동일한 createTaintNode / declassifyNodeTag /                *)
(* computeLineageDecision.                                                 *)
(*                                                                         *)
(* 기존 snapshot 모델(TaintLineage.tla)과의 차이 2가지:                    *)
(*  1. AddTag 전이 추가 — 생성 후에도 태그가 "늘어날" 수 있다.             *)
(*  2. "노드당 sink 1회 통과" 단순화 제거 — 태그가 늘 수 있으므로          *)
(*     "깨끗하게 통과 → 사후 오염 → 재통과"라는 live 고유 위험 시나리오를  *)
(*     탐색해야 한다. exfiltrated가 통과 시점 태그 스냅샷을 기록하므로     *)
(*     각 통과는 독립 기록되고, 같은 태그의 재통과는 집합 멱등이라 상태를  *)
(*     늘리지 않는다.                                                      *)
(***************************************************************************)
EXTENDS FiniteSets

CONSTANT Nodes    \* 유한 노드 집합 (상태 폭발 관리를 위해 기본 3개)

Tags == {"SENSITIVE", "UNTRUSTED"}

Trifecta(T) == Tags \subseteq T

VARIABLES
    created,     \* 생성된 노드 집합                  <-> lineageStore
    tags,        \* [Nodes -> SUBSET Tags] 유효 태그  <-> TaintNode.tags
    parents,     \* [Nodes -> SUBSET Nodes]           <-> TaintNode.parents (생성 후 불변)
    exfiltrated  \* {[node, tagsAtExit]} — 통과 "시점" 태그 스냅샷

vars == <<created, tags, parents, exfiltrated>>

Init ==
    /\ created = {}
    /\ tags = [n \in Nodes |-> {}]
    /\ parents = [n \in Nodes |-> {}]
    /\ exfiltrated = {}

(***************************************************************************)
(* 자손 계산 — cascadeDown이 따라가는 방향 그 자체.                        *)
(*                                                                         *)
(* Desc1은 "S의 자식들"(parents가 S와 겹치는 노드)을 한 단계 더한다.       *)
(* 노드가 최대 4개이므로 4회 언롤이면 어떤 체인도 포화된다 (RECURSIVE 불필요). *)
(*                                                                         *)
(* ★ 단방향의 구조적 보장: 이 정의는 parents를 "거꾸로 읽어" 자식 방향으로만 *)
(* 내려간다. 조상 집합을 계산하는 수식은 이 모듈에 존재하지 않으므로,      *)
(* AddTag가 조상의 태그를 바꾸는 것은 표현 자체가 불가능하다 —             *)
(* cascadeDown이 childIndex(부모→자식)만 따라가는 코드와 1:1 대응.         *)
(***************************************************************************)
Desc1(S) == S \cup {m \in created : parents[m] \cap S # {}}

DescendantsOf(n) ==
    LET s1 == Desc1({n})
        s2 == Desc1(s1)
        s3 == Desc1(s2)
        s4 == Desc1(s3)
    IN s4 \ {n}

(***************************************************************************)
(* CreateNode  <->  lineage.ts createTaintNode (기존 모델과 동일)          *)
(* tags' = own ∪ ⋃ parents.tags (생성 시점 전파), ps ⊆ created (DAG).      *)
(***************************************************************************)
CreateNode(n, own, ps) ==
    /\ n \notin created
    /\ ps \subseteq created
    /\ created' = created \cup {n}
    /\ parents' = [parents EXCEPT ![n] = ps]
    /\ tags' = [tags EXCEPT ![n] = own \cup UNION {tags[p] : p \in ps}]
    /\ UNCHANGED exfiltrated

(***************************************************************************)
(* AddTag  <->  lineage.ts addNodeTags + cascadeDown (live 모드)           *)
(*                                                                         *)
(* - n에 t를 추가하고, n의 "자손 전부"에게 하향 전파한다.                  *)
(* - guard t ∉ tags[n]: 코드의 "추가분만 전파"(재추가는 no-op) — no-op     *)
(*   전이를 제거해 상태 그래프만 줄인다 (도달 가능 상태는 불변).           *)
(* - 전파는 태그 "추가"만 한다 — 제거하는 항이 없다 (전파/정화 비대칭).    *)
(***************************************************************************)
AddTag(n, t) ==
    /\ n \in created
    /\ t \notin tags[n]
    /\ tags' = [m \in Nodes |->
                  IF m = n \/ m \in DescendantsOf(n) THEN tags[m] \cup {t} ELSE tags[m]]
    /\ UNCHANGED <<created, parents, exfiltrated>>

(***************************************************************************)
(* Declassify  <->  lineage.ts declassifyNodeTag (기존 모델과 동일)        *)
(* 그 노드 하나만 — 자식 갱신 항 없음(비대칭). parents 불변(소급 금지).   *)
(***************************************************************************)
Declassify(n, t) ==
    /\ n \in created
    /\ t \in tags[n]
    /\ tags' = [tags EXCEPT ![n] = @ \ {t}]
    /\ UNCHANGED <<created, parents, exfiltrated>>

(***************************************************************************)
(* ReachSink  <->  index.ts computeLineageDecision (judgmentMode="lineage")*)
(*                                                                         *)
(* 기존 모델과 달리 "노드당 1회" guard가 없다 — AddTag로 태그가 늘 수      *)
(* 있으므로 재통과를 허용해야 "통과 후 오염 → 재통과"가 탐색된다.          *)
(* 통과 시점 태그가 스냅샷으로 기록되므로 각 통과는 독립적으로 판정된다.   *)
(***************************************************************************)
ReachSink(n) ==
    /\ n \in created
    /\ ~Trifecta(tags[n])
    /\ exfiltrated' = exfiltrated \cup {[node |-> n, tagsAtExit |-> tags[n]]}
    /\ UNCHANGED <<created, tags, parents>>

Next ==
    \/ \E n \in Nodes : \E own \in SUBSET Tags : \E ps \in SUBSET created :
           CreateNode(n, own, ps)
    \/ \E n \in Nodes, t \in Tags : AddTag(n, t)
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

\* ★ 핵심 안전 속성: 트라이펙타 값은 어떤 실행 순서로도(사후 오염·재통과 포함)
\*   정화되지 않은 채 sink를 통과하지 못한다.
SinkSafety == \A e \in exfiltrated : ~Trifecta(e.tagsAtExit)

\* live 고유 시나리오 전용 보조 불변식: 같은 노드가 "태그가 늘어난 채"(진부분집합
\* 관계) 재통과했고 그 재통과가 트라이펙타면 위반. 태그 증가는 AddTag로만 가능하므로,
\* 이 불변식의 반례에는 반드시 AddTag가 등장한다 — sanity check(차단 guard 제거
\* 실험)에서 "깨끗 통과 → AddTag 오염 → 재통과" 경로를 정확히 드러내는 용도.
\* 본 모델에서는 SinkSafety가 함의하므로 자명하게 성립한다.
GrowthReExitSafety ==
    \A e1, e2 \in exfiltrated :
        (e1.node = e2.node /\ e1.tagsAtExit \subseteq e2.tagsAtExit /\ e1.tagsAtExit # e2.tagsAtExit)
            => ~Trifecta(e2.tagsAtExit)

\* 구조 불변식: 부모는 항상 자기보다 먼저 생성된 다른 노드 (DAG — 역류·사이클 불가)
ParentsExist == \A n \in created : parents[n] \subseteq created \ {n}

\* 미생성 노드는 태그도 부모도 없다 (AddTag·cascade가 created 밖으로 새지 않음도 검증)
Unborn == \A n \in Nodes \ created : tags[n] = {} /\ parents[n] = {}

==================================================================================
