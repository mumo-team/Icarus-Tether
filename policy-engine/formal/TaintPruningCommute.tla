--------------------------- MODULE TaintPruningCommute ---------------------------
(***************************************************************************)
(* 가지치기 교환성(commutation) — "prune과 미래 연산이 교환하는가":        *)
(* 같은 연산 시퀀스를 (a) 가지치기가 낀 실세계와 (b) 가지치기가 전혀 없는  *)
(* 이상세계에서 lockstep으로 실행했을 때 sink 판정이 항상 같은가?          *)
(*                                                                         *)
(* ★ 2단계(수정판 — 현재 파일): "재오염 가능 묘비" 수정을 반영한 모델.     *)
(* 1단계 버그 재현판(수정 전 의미론, CommuteSafety 위반 5스텝 반례)은      *)
(* git 이력에 있다. 재현판이 찾은 반례 양방향:                             *)
(*  - 유출: prune 후 조상 addNodeTags(live cascade)가 묘비에서 절단돼      *)
(*    묘비 참조 값이 이상세계 차단 / 실세계 통과                           *)
(*  - 과차단: "묘비=무조건 깨끗" 취급이라 재오염 묘비를 잡은 VALUE_MATCH   *)
(*    에서 안전 바닥이 오발동                                              *)
(*                                                                         *)
(* 수정 의미론 (lineage.ts·shadow.ts에 이식된 것과 1:1):                   *)
(*  - 묘비 = {resultTokens, tags, parents} — tags는 prune 시점 {}(clean    *)
(*    guard), 이후 cascadeDown 관통으로만 증가 (grow-only, 정화 불가).     *)
(*  - prune이 childIndex 엣지 유지 → cascade가 묘비를 관통(잔존 tags 적재  *)
(*    + 자손 계속). childless 판정은 "live 자식 없음".                     *)
(*  - 판정 5곳이 묘비 태그 반영: evidence unionTags / 안전 바닥            *)
(*    resolvedTaint / 생성 상속 / sessionHasLiveTag / frontier.            *)
(*                                                                         *)
(* 메커니즘을 정직하게 모델링: 실세계는 두 저장소(tagsL = live 그래프의    *)
(* TaintNode.tags, tagsT = 묘비 저장소의 잔존 tags)로 나뉘고, 이상세계     *)
(* (tagsI)는 단일 저장소다. TLC가 "두 저장소 부기가 어떤 연산 인터리빙     *)
(* 에서도 단일 저장소와 판정 동치"를 검사한다 — 수식이 정의상 같아지는     *)
(* 공허한 증명이 아니다: prune이 저장소를 옮기고, Declassify는 live        *)
(* 저장소만 만지며, cascade는 대상 저장소를 갈라 쓴다.                     *)
(*                                                                         *)
(* 범위 제한: 묘비에 대한 직접 addNodeTags는 두 세계 모두 전이 제외 —      *)
(* 코드가 throw(fail-closed)로 "시끄럽게" 실패하는 문서화된 한계라,        *)
(* 이 모델이 찾는 "조용한" 발산과 구분된다. cascade 경유 재오염(관통)이    *)
(* 조용한 경로의 전부이며 그것이 여기서 증명된다.                          *)
(***************************************************************************)
EXTENDS FiniteSets

CONSTANT Nodes

Tags == {"SENSITIVE", "UNTRUSTED"}

VARIABLES
    created,   \* 생성된 노드 집합 (두 세계 공유 — 같은 이벤트 스트림)
    parents,   \* [Nodes -> SUBSET Nodes] (공유 — 그래프 구조 동일, 소급 금지)
    pruned,    \* 실세계에서 묘비화된 노드 (이상세계에는 prune 없음)
    tagsL,     \* 실세계 live 저장소     <-> lineageStore의 TaintNode.tags
    tagsT,     \* 실세계 묘비 저장소     <-> tombstoneStore의 Tombstone.tags
    tagsI      \* 이상세계(never-pruned) 단일 저장소

vars == <<created, parents, pruned, tagsL, tagsT, tagsI>>

Live == created \ pruned

\* 실세계 판정이 읽는 유효 태그 — 노드가 어느 저장소에 있든 (tagsOfAny와 1:1)
TagsOf(n) == IF n \in pruned THEN tagsT[n] ELSE tagsL[n]

Init ==
    /\ created = {}
    /\ parents = [n \in Nodes |-> {}]
    /\ pruned = {}
    /\ tagsL = [n \in Nodes |-> {}]
    /\ tagsT = [n \in Nodes |-> {}]
    /\ tagsI = [n \in Nodes |-> {}]

(***************************************************************************)
(* 자손 계산 — 수정 후 cascade는 묘비를 관통하므로 실세계도 전 노드 경유.  *)
(* (childIndex 엣지가 prune에서 삭제되지 않는다는 코드 사실의 표현.)       *)
(* 노드가 최대 4개이므로 4회 언롤이면 어떤 체인도 포화된다.                *)
(***************************************************************************)
FullDesc1(S) == S \cup {m \in created : parents[m] \cap S # {}}
FullDescendantsOf(n) ==
    LET s1 == FullDesc1({n})
        s2 == FullDesc1(s1)
        s3 == FullDesc1(s2)
        s4 == FullDesc1(s3)
    IN s4 \ {n}

(***************************************************************************)
(* CreateNode  <->  createTaintNode — 상속이 묘비 태그 포함 (수정 ③:       *)
(* tagsOfAny). ps ⊆ created — 묘비 부모 허용(묘비 참조 연결). own·ps       *)
(* 비결정 = resolveParents 3층 + 태그 분류의 과근사.                       *)
(***************************************************************************)
CreateNode(n, own, ps) ==
    /\ n \notin created
    /\ ps \subseteq created
    /\ created' = created \cup {n}
    /\ parents' = [parents EXCEPT ![n] = ps]
    /\ tagsL' = [tagsL EXCEPT ![n] = own \cup UNION {TagsOf(p) : p \in ps}]
    /\ tagsI' = [tagsI EXCEPT ![n] = own \cup UNION {tagsI[p] : p \in ps}]
    /\ UNCHANGED <<pruned, tagsT>>

(***************************************************************************)
(* AddTag  <->  addNodeTags + cascadeDown(묘비 관통, 수정 ②) — 같은 지연   *)
(* 오염 발견 이벤트. 실세계는 live 자손을 tagsL에, 묘비 자손을 tagsT에     *)
(* 적재하며 관통한다. guard는 실세계 기준(n ∈ Live — 묘비 직접 재오염은    *)
(* throw로 전이 제외, 재추가 no-op 제거).                                  *)
(***************************************************************************)
AddTag(n, t) ==
    /\ n \in Live
    /\ t \notin tagsL[n]
    /\ LET hit == {n} \cup FullDescendantsOf(n) IN
       /\ tagsL' = [m \in Nodes |->
                      IF m \in hit /\ m \notin pruned THEN tagsL[m] \cup {t} ELSE tagsL[m]]
       /\ tagsT' = [m \in Nodes |->
                      IF m \in hit /\ m \in pruned THEN tagsT[m] \cup {t} ELSE tagsT[m]]
       /\ tagsI' = [m \in Nodes |->
                      IF m \in hit THEN tagsI[m] \cup {t} ELSE tagsI[m]]
    /\ UNCHANGED <<created, parents, pruned>>

(***************************************************************************)
(* Declassify  <->  declassifyNodeTag — live 저장소만 (묘비 태그는         *)
(* grow-only, 정화 불가 = fail-closed). 그 노드 하나만(비대칭).            *)
(***************************************************************************)
Declassify(n, t) ==
    /\ n \in Live
    /\ t \in tagsL[n]
    /\ tagsL' = [tagsL EXCEPT ![n] = @ \ {t}]
    /\ tagsI' = [tagsI EXCEPT ![n] = @ \ {t}]
    /\ UNCHANGED <<created, parents, pruned, tagsT>>

(***************************************************************************)
(* Prune  <->  pruneSessionLineage — 저장소 이동. guard = 깨끗 + "live     *)
(* 자식 없음"(묘비 자식은 prune을 막지 않음 — 연쇄 유지). 이상세계 무변화. *)
(***************************************************************************)
Prune(n) ==
    /\ n \in Live
    /\ tagsL[n] = {}
    /\ ~\E m \in Live : n \in parents[m]
    /\ pruned' = pruned \cup {n}
    /\ tagsT' = [tagsT EXCEPT ![n] = tagsL[n]]
    /\ UNCHANGED <<created, parents, tagsL, tagsI>>

Next ==
    \/ \E n \in Nodes : \E own \in SUBSET Tags : \E ps \in SUBSET created :
           CreateNode(n, own, ps)
    \/ \E n \in Nodes, t \in Tags : AddTag(n, t)
    \/ \E n \in Nodes, t \in Tags : Declassify(n, t)
    \/ \E n \in Nodes : Prune(n)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* 판정 — 프로브 <<kind, R>>: NONE(무참조 폴백) / REF(MCP_REF, 바닥 미발동)*)
(* / MATCH(VALUE_MATCH, 오염 미식별 시 바닥). R ⊆ created — 묘비 참조도    *)
(* 해소된다(resultTokens 보존). 실세계는 TagsOf(두 저장소), 이상세계는     *)
(* tagsI(단일 저장소)로 같은 수식을 평가한다.                              *)
(***************************************************************************)

\* frontier: 묘비도 후보·커버 참여 (수정 ⑤ — isLiveTaintRoot의 tagsOfAny)
FrontierR == {n \in created :
                \E t \in TagsOf(n) : \A p \in parents[n] : t \notin TagsOf(p)}
FrontierI == {n \in created :
                \E t \in tagsI[n] : \A p \in parents[n] : t \notin tagsI[p]}

\* evidence: 묘비 참조도 자기 태그 기여 (수정 ①), 바닥 resolvedTaint도 (수정 ②)
EvTagsR(kind, R) ==
    LET refTags == UNION {TagsOf(n) : n \in R}
        resolvedTaint == \E n \in R : TagsOf(n) # {}
        floor == kind = "NONE" \/ (kind = "MATCH" /\ ~resolvedTaint)
    IN IF floor THEN refTags \cup UNION {TagsOf(n) : n \in FrontierR} ELSE refTags

EvTagsI(kind, R) ==
    LET refTags == UNION {tagsI[n] : n \in R}
        resolvedTaint == \E n \in R : tagsI[n] # {}
        floor == kind = "NONE" \/ (kind = "MATCH" /\ ~resolvedTaint)
    IN IF floor THEN refTags \cup UNION {tagsI[n] : n \in FrontierI} ELSE refTags

\* 비대칭 규칙: 차단 ⇔ S ∈ 값-계보 ∧ (U ∈ 값-계보 ∨ 세션에 U 보유자 존재)
\* sessionHasLiveTag는 묘비 잔존 태그도 센다 (수정 ④) — 전 created를 TagsOf로.
BlockedR(kind, R) ==
    /\ "SENSITIVE" \in EvTagsR(kind, R)
    /\ \/ "UNTRUSTED" \in EvTagsR(kind, R)
       \/ \E n \in created : "UNTRUSTED" \in TagsOf(n)

BlockedI(kind, R) ==
    /\ "SENSITIVE" \in EvTagsI(kind, R)
    /\ \/ "UNTRUSTED" \in EvTagsI(kind, R)
       \/ \E n \in created : "UNTRUSTED" \in tagsI[n]

(***************************************************************************)
(* 불변식                                                                  *)
(***************************************************************************)

TypeOK ==
    /\ created \subseteq Nodes
    /\ tagsL \in [Nodes -> SUBSET Tags]
    /\ tagsT \in [Nodes -> SUBSET Tags]
    /\ tagsI \in [Nodes -> SUBSET Tags]
    /\ parents \in [Nodes -> SUBSET Nodes]
    /\ pruned \subseteq created

\* ★ 교환성: 모든 프로브에서 실세계와 이상세계 판정이 같다 —
\*   "가지치기는 어떤 연산 인터리빙 아래서도 판정에 관측 불가능하다".
CommuteSafety ==
    /\ BlockedR("NONE", {}) = BlockedI("NONE", {})
    /\ \A R \in (SUBSET created) \ {{}} :
           /\ BlockedR("REF", R) = BlockedI("REF", R)
           /\ BlockedR("MATCH", R) = BlockedI("MATCH", R)

\* 방향 분해 — 반례 발생 시 트레이스를 방향별로 뽑기 위한 약화판 2종.
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

\* 판정 이전 수준의 더 강한 동치: 저장소 분할이 태그 자체를 보존한다.
\* (CommuteSafety ⊂ StoreFaithful의 따름 — 그래도 둘 다 걸어 이중 확인.)
StoreFaithful == \A n \in created : TagsOf(n) = tagsI[n]

ParentsExist == \A n \in created : parents[n] \subseteq created \ {n}

Unborn == \A n \in Nodes \ created : tagsL[n] = {} /\ tagsT[n] = {} /\ parents[n] = {}

==================================================================================
