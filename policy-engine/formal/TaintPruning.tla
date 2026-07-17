------------------------------ MODULE TaintPruning ------------------------------
(***************************************************************************)
(* 가지치기(묘비 압축) 안전성 — "가지치기 전후 판정 불변"의 전수 탐색 증명. *)
(*                                                                         *)
(* 실제 코드 대응: policy-engine/src/lineage.ts의 pruneSessionLineage      *)
(* (묘비화)와 tombstoneStore, 판정 경로 computeLineageDecision(index.ts)   *)
(* → collectLineageEvidence(shadow.ts) → resolveParents(lineage.ts).       *)
(* fast-check 실측(pruning.test.ts ★판정 보존)의 설계판 전수 증명이다.     *)
(*                                                                         *)
(* 모델링 핵심 결정 3가지:                                                 *)
(*  1. 묘비 = pruned 집합. 코드의 묘비가 id+resultTokens를 보존한다는      *)
(*     사실은 "pruned 노드에 대한 프로브 참조(REF/MATCH)가 여전히          *)
(*     해소된다"로 표현한다(프로브의 R ⊆ created — pruned 포함 가능).      *)
(*     반면 태그·프론티어·세션축 계산은 Live(실그래프)만 읽는다 —          *)
(*     묘비 태그 무기여(lineage.ts resolveParents/createTaintNode의        *)
(*     graph.get(id) = undefined 분기)와 1:1.                              *)
(*  2. 판정은 전이(ReachSink)가 아니라 상태 함수 Blocked(kind, R)이다.     *)
(*     전이+exfiltrated 스냅샷 방식은 "가지치기 전 스냅샷 보관"이 필요해   *)
(*     상태가 폭발한다. 상태 함수로 두면 PruneSafety가 "모든 도달 가능     *)
(*     상태 × 모든 프로브"에서 실세계/이상세계 판정 동일을 검사한다 —      *)
(*     Prune 전이는 pruned만 바꾸고 이상세계 판정은 pruned와 무관하므로,   *)
(*     이 불변식이 성립하면 "Prune 직전 판정 = 직후 판정"(테스트의 ★속성) *)
(*     이 따라 나온다. 더불어 prune 뒤 CreateNode/Declassify가 낀 미래     *)
(*     상태에서도 성립하는 더 강한 보존이다.                               *)
(*  3. 이상(never-pruned) 세계의 태그는 별도 변수가 아니라 ghost 재사용:   *)
(*     pruned 노드의 tags는 prune 시점 값에 동결된다(AddTag/Declassify     *)
(*     guard가 Live 한정 — 코드의 addNodeTags throw(fail-closed)·          *)
(*     declassifyNodeTag no-op과 대응). Prune guard가 tags = {}를          *)
(*     요구하므로 동결값은 항상 {} — PrunedClean 불변식이 이를 검증한다.   *)
(*                                                                         *)
(* ★ 이 모델이 다루지 않는 것 (별도 모델 TaintPruningCommute에서 다룸):   *)
(*   "prune과 미래 연산의 교환성". AddTag의 cascade는 수정 전 코드 그대로  *)
(*   묘비에서 절단된다(당시 prune이 childIndex 엣지를 지웠다).             *)
(*                                                                         *)
(* ★★ 의미론 시점 주의: 이 모델은 "재오염 가능 묘비" 수정 전의 절단        *)
(*   의미론을 보존 기록한 것이다 — 수정 전 코드에서도 상태-점별 보존       *)
(*   (PruneSafety)은 성립했음을 증명한다 (fast-check ★판정 보존이 통과하던 *)
(*   이유). 그 의미론의 구멍(교환성)과 수정 후 최종 의미론의 완전한 증명은 *)
(*   TaintPruningCommute.tla(수정판 — cascade 관통, 두-저장소)가 담당한다. *)
(*   현재 lineage.ts와의 대응은 Commute 모델을 기준으로 볼 것.             *)
(*                                                                         *)
(* argTags·볼트 원본 재전송(containsVaultOriginal)은 그래프 상태와 무관해  *)
(* 가지치기의 영향을 받지 않으므로 모델에서 제외한다 (README 범위 제한).   *)
(***************************************************************************)
EXTENDS FiniteSets

CONSTANT Nodes    \* 유한 노드 집합 (기본 4개 — exfiltrated 변수가 없어 live 모델보다 작다)

Tags == {"SENSITIVE", "UNTRUSTED"}

VARIABLES
    created,   \* 생성된 노드 집합 (역사 전체)      <-> lineageStore에 존재했던 모든 노드
    tags,      \* [Nodes -> SUBSET Tags] 유효 태그  <-> TaintNode.tags (pruned는 {}에 동결)
    parents,   \* [Nodes -> SUBSET Nodes] 생성 후 불변 <-> TaintNode.parents (소급 금지)
    pruned     \* 묘비화된 노드 집합                <-> tombstoneStore의 키 집합

vars == <<created, tags, parents, pruned>>

\* 실그래프(lineageStore에 지금 실존하는 노드) — 묘비 제외
Live == created \ pruned

Init ==
    /\ created = {}
    /\ tags = [n \in Nodes |-> {}]
    /\ parents = [n \in Nodes |-> {}]
    /\ pruned = {}

(***************************************************************************)
(* Live 자손 계산 — cascadeDown이 실제로 도달 가능한 범위.                 *)
(*                                                                         *)
(* prune은 childIndex에서 묘비를 완전히 떼어낸다(자신의 children 엔트리    *)
(* 삭제 + 부모들의 children 집합에서 자신 제거 — pruneSessionLineage).     *)
(* 따라서 cascade는 live 노드 사슬로만 흐른다: LiveDesc1이 Live 소속       *)
(* 노드만 더하므로 묘비를 경유하는 체인은 여기서 절단된다 (코드와 1:1).    *)
(* 노드가 최대 4개이므로 4회 언롤이면 어떤 체인도 포화된다.                *)
(***************************************************************************)
LiveDesc1(S) == S \cup {m \in Live : parents[m] \cap S # {}}

LiveDescendantsOf(n) ==
    LET s1 == LiveDesc1({n})
        s2 == LiveDesc1(s1)
        s3 == LiveDesc1(s2)
        s4 == LiveDesc1(s3)
    IN s4 \ {n}

(***************************************************************************)
(* CreateNode  <->  lineage.ts createTaintNode                             *)
(*                                                                         *)
(* ps ⊆ created — 묘비 부모 허용: resolveParents는 graph.has(s) ||         *)
(* tombstones.has(s)로 묘비 참조도 1순위 연결로 해소한다. 단 태그 상속은   *)
(* live 부모에게서만(ps ∩ Live) — createTaintNode의 graph.get(link.nodeId) *)
(* 가 묘비에서 undefined → continue(상속 0)와 1:1. own·ps 비결정 선택은    *)
(* resolveParents 3층 연결 + 태그 분류의 과근사 (기존 모델과 동일 스타일). *)
(***************************************************************************)
CreateNode(n, own, ps) ==
    /\ n \notin created
    /\ ps \subseteq created
    /\ created' = created \cup {n}
    /\ parents' = [parents EXCEPT ![n] = ps]
    /\ tags' = [tags EXCEPT ![n] = own \cup UNION {tags[p] : p \in ps \cap Live}]
    /\ UNCHANGED pruned

(***************************************************************************)
(* AddTag  <->  lineage.ts addNodeTags + cascadeDown (live 모드)           *)
(*                                                                         *)
(* - guard n ∈ Live: 묘비에 대한 addNodeTags는 throw(fail-closed) = 상태   *)
(*   무변경이므로 전이 자체를 제외한다 (알려진 한계로 코드에 문서화됨).    *)
(* - 전파 범위가 LiveDescendantsOf — 묘비 경유 체인 절단(위 주석 참고).    *)
(* - guard t ∉ tags[n]: 재추가 no-op 제거 (도달 가능 상태 불변).           *)
(***************************************************************************)
AddTag(n, t) ==
    /\ n \in Live
    /\ t \notin tags[n]
    /\ tags' = [m \in Nodes |->
                  IF m = n \/ m \in LiveDescendantsOf(n) THEN tags[m] \cup {t} ELSE tags[m]]
    /\ UNCHANGED <<created, parents, pruned>>

(***************************************************************************)
(* Declassify  <->  lineage.ts declassifyNodeTag                           *)
(* 그 노드 하나만(비대칭), parents 불변(소급 금지). guard n ∈ Live:        *)
(* 묘비에 대한 호출은 no-op(존재하지 않는 노드 → return)이라 전이 제외.    *)
(***************************************************************************)
Declassify(n, t) ==
    /\ n \in Live
    /\ t \in tags[n]
    /\ tags' = [tags EXCEPT ![n] = @ \ {t}]
    /\ UNCHANGED <<created, parents, pruned>>

(***************************************************************************)
(* Prune  <->  lineage.ts pruneSessionLineage의 대상 조건                  *)
(*                                                                         *)
(* guard = "태그가 전부 없어졌고(정화 완료) live 자식이 없는" 노드:        *)
(*   node.tags.size > 0 || children.size > 0 → continue 의 부정.           *)
(*   (childIndex의 children 집합에서 pruned 자식은 prune 시점에 제거되므로 *)
(*    "children 비어있음" = "live 자식 없음"과 동치.)                      *)
(* 코드의 fixpoint 루프는 단일 노드 Prune의 연쇄와 도달 상태가 같고,       *)
(* 단일 스텝 모델은 부분 완료 상태까지 검사하므로 더 강하다 — 코드 주석    *)
(* "부분 완료 상태도 안전"의 형식판.                                       *)
(* 효과는 pruned에 추가뿐 — tags[n]은 {}에 동결(ghost), parents 불변.      *)
(***************************************************************************)
Prune(n) ==
    /\ n \in Live
    /\ tags[n] = {}
    /\ ~\E m \in Live : n \in parents[m]
    /\ pruned' = pruned \cup {n}
    /\ UNCHANGED <<created, tags, parents>>

Next ==
    \/ \E n \in Nodes : \E own \in SUBSET Tags : \E ps \in SUBSET created :
           CreateNode(n, own, ps)
    \/ \E n \in Nodes, t \in Tags : AddTag(n, t)
    \/ \E n \in Nodes, t \in Tags : Declassify(n, t)
    \/ \E n \in Nodes : Prune(n)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* 판정 상태 함수 — 실세계(R 접미사) vs 이상세계(I 접미사, never-pruned)   *)
(*                                                                         *)
(* 프로브 = <<kind, R>>. pruning.test.ts의 프로브 집합                     *)
(* [{}, ...{_taintRef:[id]}]의 일반화 + resolveParents 3층 전체 커버:      *)
(*  - "NONE"  (R = {})  무참조 → 안전 바닥(frontier) 폴백                  *)
(*  - "REF"   (R ≠ {})  MCP_REF: 묘비 포함 참조 해소, 바닥 미발동(권위적)  *)
(*  - "MATCH" (R ≠ {})  VALUE_MATCH: 잡은 게 전부 깨끗(묘비 포함)이면      *)
(*             바닥 발동 — valueMatchOnlyClean(fail-open 3차 수정)의 모델. *)
(***************************************************************************)

\* isLiveTaintRoot — 실그래프: 묘비 부모는 graph.get = undefined → 태그 커버 못함
FrontierR == {n \in Live :
                \E t \in tags[n] : \A p \in parents[n] \cap Live : t \notin tags[p]}

\* 이상세계: 묘비도 살아있는(동결된 깨끗한) 노드로 취급 — 모든 부모가 커버 후보
FrontierI == {n \in created :
                \E t \in tags[n] : \A p \in parents[n] : t \notin tags[p]}

\* collectLineageEvidence의 unionTags + 안전 바닥 frontier 덧붙임 (실세계)
EvTagsR(kind, R) ==
    LET refTags == UNION {tags[n] : n \in R \cap Live}   \* 묘비 참조는 태그 무기여
        resolvedTaint == \E n \in R \cap Live : tags[n] # {}  \* 묘비 = 깨끗 취급 (안전 바닥 발동조건)
        floor == kind = "NONE" \/ (kind = "MATCH" /\ ~resolvedTaint)
    IN IF floor THEN refTags \cup UNION {tags[n] : n \in FrontierR} ELSE refTags

EvTagsI(kind, R) ==
    LET refTags == UNION {tags[n] : n \in R}
        resolvedTaint == \E n \in R : tags[n] # {}
        floor == kind = "NONE" \/ (kind = "MATCH" /\ ~resolvedTaint)
    IN IF floor THEN refTags \cup UNION {tags[n] : n \in FrontierI} ELSE refTags

\* computeLineageDecision의 비대칭 규칙: 차단 ⇔ S ∈ 값-계보 ∧ (U ∈ 값-계보 ∨ 세션에 live U)
BlockedR(kind, R) ==
    /\ "SENSITIVE" \in EvTagsR(kind, R)
    /\ \/ "UNTRUSTED" \in EvTagsR(kind, R)
       \/ \E n \in Live : "UNTRUSTED" \in tags[n]        \* sessionHasLiveTag — live 그래프만 순회

BlockedI(kind, R) ==
    /\ "SENSITIVE" \in EvTagsI(kind, R)
    /\ \/ "UNTRUSTED" \in EvTagsI(kind, R)
       \/ \E n \in created : "UNTRUSTED" \in tags[n]

(***************************************************************************)
(* 불변식                                                                  *)
(***************************************************************************)

TypeOK ==
    /\ created \subseteq Nodes
    /\ tags \in [Nodes -> SUBSET Tags]
    /\ parents \in [Nodes -> SUBSET Nodes]
    /\ pruned \subseteq created

\* ★ 핵심 안전 속성: 어떤 도달 가능 상태에서도, 어떤 프로브에 대해서도
\*   "묘비 압축된 실세계"와 "아무것도 가지치기하지 않은 이상세계"의 판정이 같다
\*   = 가지치기가 판정을 (유출 방향으로도 과차단 방향으로도) 바꾸지 않는다.
PruneSafety ==
    /\ BlockedR("NONE", {}) = BlockedI("NONE", {})
    /\ \A R \in (SUBSET created) \ {{}} :
           /\ BlockedR("REF", R) = BlockedI("REF", R)
           /\ BlockedR("MATCH", R) = BlockedI("MATCH", R)

\* 보조 렘마이자 묘비의 존재 의의: 묘비는 오염을 절대 숨기지 않는다.
\* (Prune guard tags = {} + 동결(AddTag/Declassify의 Live 한정)의 합성 결과 —
\*  PruneSafety의 등식이 성립하는 구조적 이유가 바로 이것이다.)
PrunedClean == \A n \in pruned : tags[n] = {}

\* 구조 불변식: 부모는 항상 자기보다 먼저 생성된 다른 노드 (DAG)
ParentsExist == \A n \in created : parents[n] \subseteq created \ {n}

\* 미생성 노드는 태그도 부모도 없다
Unborn == \A n \in Nodes \ created : tags[n] = {} /\ parents[n] = {}

==================================================================================
