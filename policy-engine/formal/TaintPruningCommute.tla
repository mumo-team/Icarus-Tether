--------------------------- MODULE TaintPruningCommute ---------------------------
(***************************************************************************)
(* 가지치기 교환성(commutation) — "prune과 미래 연산이 교환하는가":        *)
(* 같은 연산 시퀀스를 (a) 가지치기가 낀 실세계와 (b) 가지치기가 전혀 없는  *)
(* 이상세계에서 lockstep으로 실행했을 때 sink 판정이 항상 같은가?          *)
(*                                                                         *)
(* TaintPruning.tla(상태-점별 보존, PruneSafety 위반 0)보다 강한 속성이다: *)
(* 그 모델은 "묘비가 그래프에 있던 정보를 잃지 않음"을 증명하지만, prune   *)
(* "이후"의 연산이 두 세계에서 다르게 전개되는 경우는 정의상 다루지 않는다.*)
(*                                                                         *)
(* ★ 1단계(버그 재현판): 이 파일은 현재 코드(lineage.ts)의 의미론을 그대로 *)
(* 모델링한다 — prune이 childIndex 엣지를 지우므로(pruneSessionLineage의   *)
(* perSession.delete) 이후의 cascadeDown(addNodeTags live 전파)이 묘비를   *)
(* 관통하지 못한다. 기대 결과: CommuteSafety 위반 —                        *)
(*                                                                         *)
(*   Create(a, own={U}) → Create(p, ps={a}) → Declassify(p, U) → Prune(p)  *)
(*   → Create(m, ps={p}) (묘비 참조) → AddTag(a, S) (지연 오염 발견)       *)
(*                                                                         *)
(*   실세계: cascade가 a에서 절단(p는 a의 children에서 제거됨) → m은 S     *)
(*   없음 → REF{m} 프로브 통과. 이상세계: a→p→m 관통 전파 → m이 S 보유     *)
(*   ∧ 세션 U(a) → 차단. 판정 상이 = 유출 방향 구멍.                       *)
(*                                                                         *)
(* fast-check(pruning.test.ts ★판정 보존)는 prune을 시퀀스 마지막에 두므로 *)
(* 이 시나리오를 관측하지 못한다.                                          *)
(*                                                                         *)
(* 두 세계는 created/parents/pruned를 공유하고(같은 이벤트 스트림·같은     *)
(* 그래프 구조) 태그만 두 벌이다: tagsR = 실세계(절단), tagsI = 이상세계   *)
(* (관통). 전이 guard는 실세계 기준 — 시스템을 구동하는 것은 실세계다.     *)
(*                                                                         *)
(* 범위 제한: 묘비에 대한 직접 addNodeTags는 두 세계 모두 전이 제외 —      *)
(* 코드가 throw(fail-closed)로 "시끄럽게" 실패하는 문서화된 한계라,        *)
(* 이 모델이 찾는 "조용한" 발산(cascade 절단은 오류 없이 지나감)과 구분.   *)
(***************************************************************************)
EXTENDS FiniteSets

CONSTANT Nodes

Tags == {"SENSITIVE", "UNTRUSTED"}

VARIABLES
    created,   \* 생성된 노드 집합 (두 세계 공유)
    parents,   \* [Nodes -> SUBSET Nodes] (두 세계 공유 — 구조 동일)
    pruned,    \* 실세계에서 묘비화된 노드 (이상세계에는 prune 없음)
    tagsR,     \* 실세계 태그 — cascade가 묘비에서 절단 (현재 코드)
    tagsI      \* 이상세계 태그 — prune이 없었다면의 관통 전파

vars == <<created, parents, pruned, tagsR, tagsI>>

Live == created \ pruned

Init ==
    /\ created = {}
    /\ parents = [n \in Nodes |-> {}]
    /\ pruned = {}
    /\ tagsR = [n \in Nodes |-> {}]
    /\ tagsI = [n \in Nodes |-> {}]

(* 실세계 자손: live 사슬만 (prune의 childIndex 엣지 삭제 = 묘비 경유 절단) *)
LiveDesc1(S) == S \cup {m \in Live : parents[m] \cap S # {}}
LiveDescendantsOf(n) ==
    LET s1 == LiveDesc1({n})
        s2 == LiveDesc1(s1)
        s3 == LiveDesc1(s2)
        s4 == LiveDesc1(s3)
    IN s4 \ {n}

(* 이상세계 자손: 전 노드 경유 (prune이 없었다면 모든 사슬이 살아있다) *)
FullDesc1(S) == S \cup {m \in created : parents[m] \cap S # {}}
FullDescendantsOf(n) ==
    LET s1 == FullDesc1({n})
        s2 == FullDesc1(s1)
        s3 == FullDesc1(s2)
        s4 == FullDesc1(s3)
    IN s4 \ {n}

(***************************************************************************)
(* CreateNode — 실세계: live 부모에게서만 상속(묘비는 graph.get undefined  *)
(* → 상속 0). 이상세계: 모든 부모에게서 상속 (p가 살아있었다면 물려줬을    *)
(* 태그까지).                                                              *)
(***************************************************************************)
CreateNode(n, own, ps) ==
    /\ n \notin created
    /\ ps \subseteq created
    /\ created' = created \cup {n}
    /\ parents' = [parents EXCEPT ![n] = ps]
    /\ tagsR' = [tagsR EXCEPT ![n] = own \cup UNION {tagsR[p] : p \in ps \cap Live}]
    /\ tagsI' = [tagsI EXCEPT ![n] = own \cup UNION {tagsI[p] : p \in ps}]
    /\ UNCHANGED pruned

(***************************************************************************)
(* AddTag — 같은 지연 오염 발견 이벤트가 두 세계에서 다르게 전파된다:      *)
(* 실세계는 LiveDescendants(절단), 이상세계는 FullDescendants(관통).       *)
(* guard는 실세계 기준(n ∈ Live, 재추가 no-op 제거).                       *)
(***************************************************************************)
AddTag(n, t) ==
    /\ n \in Live
    /\ t \notin tagsR[n]
    /\ tagsR' = [m \in Nodes |->
                   IF m = n \/ m \in LiveDescendantsOf(n) THEN tagsR[m] \cup {t} ELSE tagsR[m]]
    /\ tagsI' = [m \in Nodes |->
                   IF m = n \/ m \in FullDescendantsOf(n) THEN tagsI[m] \cup {t} ELSE tagsI[m]]
    /\ UNCHANGED <<created, parents, pruned>>

(* 같은 정화 이벤트 — 두 세계 모두 그 노드 하나에서 t 제거 (비대칭 유지) *)
Declassify(n, t) ==
    /\ n \in Live
    /\ t \in tagsR[n]
    /\ tagsR' = [tagsR EXCEPT ![n] = @ \ {t}]
    /\ tagsI' = [tagsI EXCEPT ![n] = @ \ {t}]
    /\ UNCHANGED <<created, parents, pruned>>

(* Prune — 실세계에만 존재. guard는 실세계 조건 (깨끗 + live 자식 없음). *)
Prune(n) ==
    /\ n \in Live
    /\ tagsR[n] = {}
    /\ ~\E m \in Live : n \in parents[m]
    /\ pruned' = pruned \cup {n}
    /\ UNCHANGED <<created, parents, tagsR, tagsI>>

Next ==
    \/ \E n \in Nodes : \E own \in SUBSET Tags : \E ps \in SUBSET created :
           CreateNode(n, own, ps)
    \/ \E n \in Nodes, t \in Tags : AddTag(n, t)
    \/ \E n \in Nodes, t \in Tags : Declassify(n, t)
    \/ \E n \in Nodes : Prune(n)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* 판정 — TaintPruning.tla와 동일한 프로브·판정 함수, 세계별 태그로.       *)
(***************************************************************************)

FrontierR == {n \in Live :
                \E t \in tagsR[n] : \A p \in parents[n] \cap Live : t \notin tagsR[p]}
FrontierI == {n \in created :
                \E t \in tagsI[n] : \A p \in parents[n] : t \notin tagsI[p]}

EvTagsR(kind, R) ==
    LET refTags == UNION {tagsR[n] : n \in R \cap Live}
        resolvedTaint == \E n \in R \cap Live : tagsR[n] # {}
        floor == kind = "NONE" \/ (kind = "MATCH" /\ ~resolvedTaint)
    IN IF floor THEN refTags \cup UNION {tagsR[n] : n \in FrontierR} ELSE refTags

EvTagsI(kind, R) ==
    LET refTags == UNION {tagsI[n] : n \in R}
        resolvedTaint == \E n \in R : tagsI[n] # {}
        floor == kind = "NONE" \/ (kind = "MATCH" /\ ~resolvedTaint)
    IN IF floor THEN refTags \cup UNION {tagsI[n] : n \in FrontierI} ELSE refTags

BlockedR(kind, R) ==
    /\ "SENSITIVE" \in EvTagsR(kind, R)
    /\ \/ "UNTRUSTED" \in EvTagsR(kind, R)
       \/ \E n \in Live : "UNTRUSTED" \in tagsR[n]

BlockedI(kind, R) ==
    /\ "SENSITIVE" \in EvTagsI(kind, R)
    /\ \/ "UNTRUSTED" \in EvTagsI(kind, R)
       \/ \E n \in created : "UNTRUSTED" \in tagsI[n]

(***************************************************************************)
(* 불변식                                                                  *)
(***************************************************************************)

TypeOK ==
    /\ created \subseteq Nodes
    /\ tagsR \in [Nodes -> SUBSET Tags]
    /\ tagsI \in [Nodes -> SUBSET Tags]
    /\ parents \in [Nodes -> SUBSET Nodes]
    /\ pruned \subseteq created

\* ★ 교환성: 모든 프로브에서 실세계와 이상세계 판정이 같다.
\*   1단계(현재 코드 의미론)에서는 위반이 기대된다 — 반례 = cascade 절단 경로.
CommuteSafety ==
    /\ BlockedR("NONE", {}) = BlockedI("NONE", {})
    /\ \A R \in (SUBSET created) \ {{}} :
           /\ BlockedR("REF", R) = BlockedI("REF", R)
           /\ BlockedR("MATCH", R) = BlockedI("MATCH", R)

\* 방향 분해 — 반례 트레이스를 방향별로 뽑기 위한 약화판 2종.
\*  유출 방향(보안 구멍): 이상세계는 차단하는데 실세계가 통과시킨다.
CommuteNoLeak ==
    /\ BlockedI("NONE", {}) => BlockedR("NONE", {})
    /\ \A R \in (SUBSET created) \ {{}} :
           /\ BlockedI("REF", R) => BlockedR("REF", R)
           /\ BlockedI("MATCH", R) => BlockedR("MATCH", R)

\*  과차단 방향(정밀도 손실): 이상세계는 통과시키는데 실세계가 차단한다.
CommuteNoOverblock ==
    /\ BlockedR("NONE", {}) => BlockedI("NONE", {})
    /\ \A R \in (SUBSET created) \ {{}} :
           /\ BlockedR("REF", R) => BlockedI("REF", R)
           /\ BlockedR("MATCH", R) => BlockedI("MATCH", R)

\* 절단은 태그를 "덜 퍼뜨리는" 방향으로만 발산한다 — 실세계 태그는 항상
\* 이상세계의 부분집합 (발산이 유출 방향임의 구조적 근거: 과차단은 없다).
WorldMono == \A n \in Nodes : tagsR[n] \subseteq tagsI[n]

ParentsExist == \A n \in created : parents[n] \subseteq created \ {n}

Unborn == \A n \in Nodes \ created : tagsR[n] = {} /\ parents[n] = {}

==================================================================================
