------------------------ MODULE TaintDestructiveHITL ------------------------
(***************************************************************************)
(* 파괴적 액션 게이트("비신뢰가 유발한 파괴"만 차단) + HITL 오버라이드의    *)
(* 안전성 모델. 설계 검토에서 발견한 교차-게이트 구멍(공유 지문 키)의       *)
(* 재현 스위치(SharedKeys)를 포함한다 — 기본(cfg)은 수정판(FALSE).         *)
(*                                                                         *)
(* 실제 코드 대응 (구현 예정 — 이 모델이 의미론의 선행 확정본):             *)
(*  - 판정: index.ts computeDestructiveDecision — "destructiveTools 등록   *)
(*    도구 호출 AND 세션 U-집합 비어있지 않음 → 차단" (U-집합은            *)
(*    sessionHasLiveTag의 보유자 집합 = lineage.ts collectLiveTagHolders). *)
(*  - HITL: hitl.ts offerOverride/consumeApprovalIfMatching에 gate 판별자  *)
(*    ("exfil"|"destructive")를 지문에 포함 — offer 공간 서로소.           *)
(*  - 승인 지문: 제안 시점 U-집합 스냅샷(collectLiveTagHolders를           *)
(*    LineageEvidence로 접어 lineageFingerprintOf에 태움). 소비 시점       *)
(*    U-집합과 일치할 때만 1회 소비(TOCTOU 재검증 — TaintHITL 2단계의      *)
(*    동형 메커니즘을 다른 상태 공간(U-집합)에 재사용).                    *)
(*                                                                         *)
(* TaintHITL.tla가 커버하지 못하는 새 축 3가지가 이 모델의 존재 이유:      *)
(*  1. 판정 술어가 다르다 — 값-계보 트라이펙타가 아니라 세션 U-집합 존재.  *)
(*  2. 변이 알파벳이 다르다 — strength 승격이 아니라 U-집합의 증가         *)
(*     (ReadUntrusted)·감소(DeclassifyU)가 승인~소비 사이에 끼어든다.      *)
(*  3. 기계가 둘이다 — 유출·파괴 게이트가 offers 저장소를 공유할 때의      *)
(*     교차 간섭(SUPERSEDED/소각)은 단일 기계 모델로 표현 자체가 불가.     *)
(*                                                                         *)
(* 단순화 (기존 모델과의 관계):                                            *)
(*  - U-보유자 id 신선성: 정화된 id는 retired로 이동해 재사용 불가 —       *)
(*    코드의 tn_<uuid>(재읽기 = 새 노드 id)와 1:1. 이 덕에 "U-집합         *)
(*    집합-동치"가 코드의 노드id 기반 지문 대조와 정확히 대응한다          *)
(*    (한 번 달라진 집합은 영원히 못 돌아옴 — grow/retire 단조).           *)
(*  - 유출(exfil) 게이트는 수명주기만 모델링, taint guard 없음(과근사 —    *)
(*    offer가 언제 나든 격리 속성엔 무관). 유출 자체의 안전성·TOCTOU는     *)
(*    TaintHITL.tla 소관(전제 유지의 근거가 곧 GateIsolation).             *)
(*  - PENDING은 OFFERED에 접음(TaintHITL과 동일 — 부기 전이).              *)
(*  - 파괴 게이트 자신의 SUPERSEDED(제안 중 지문 변화→재발급)와            *)
(*    STALE(소비 시 불일치→영구 무효)은 각각 DOffer 재발급 guard와         *)
(*    DConsumeStale의 USED로 접음. 명시 상태 "SUPERSEDED"/"STALE"은        *)
(*    교차-게이트 소각 전용으로 남겨 격리 위반을 상태로 관측 가능하게 함.  *)
(*                                                                         *)
(* ★ 정직성 주석(GateIsolation의 증명력): SharedKeys=FALSE에서 교차 전이   *)
(* 4종이 구조적으로 비활성임을 TLC가 전 상태에서 확인한다 — 이는 코드      *)
(* 수정(지문에 gate 포함 = 다른 게이트의 offer가 스캔에 안 걸림)의 모델판  *)
(* 그 자체다. TRUE 변형(별도 cfg)이 3~4스텝 반례를 내놓아 구멍이 설계      *)
(* 수준에서 실재함을 보인다 — TaintHITL의 1단계(재현)→2단계(수정) 패턴의   *)
(* 축약판(재현판을 git 이력 대신 SharedKeys 스위치로 보존).                *)
(***************************************************************************)
EXTENDS FiniteSets

CONSTANTS
    UNodes,     \* 비신뢰(U) 보유자 노드 id 풀 (상태 폭발 관리를 위해 기본 2개)
    Calls,      \* 파괴적 도구 호출 지문(sessionId|toolName|args) 식별자
    SharedKeys  \* FALSE = 수정판(gate 판별자 지문), TRUE = naive 공유 키(버그 재현)

ASSUME SharedKeys \in BOOLEAN

\* hitl.ts offers Map의 상태. SUPERSEDED/STALE은 교차-게이트 소각 전용(위 주석).
Status == {"NONE", "OFFERED", "APPROVED", "REJECTED", "USED", "SUPERSEDED", "STALE"}

VARIABLES
    uSet,       \* 살아있는 U-보유자 집합        <-> sessionHasLiveTag=true인 노드들
    retired,    \* 정화돼 은퇴한 id (재사용 불가) <-> declassify된 노드 (id는 소멸 안 함)
    dStatus,    \* [Calls -> Status] 파괴 게이트 offer 상태
    dSnap,      \* [Calls -> SUBSET UNodes]      <-> ★파괴 offer의 U-집합 스냅샷 지문
    eStatus,    \* [Calls -> Status] 유출 게이트 offer 상태 (수명주기만 — 과근사)
    eKilledByD, \* 파괴 게이트 행동이 유출 offer를 SUPERSEDE/소각했는가 (격리 위반 관측자)
    dKilledByE, \* 유출 게이트 행동이 파괴 offer를 SUPERSEDE/소각했는가 (대칭)
    executed    \* {[call, uAtExit, snapAtOffer, via]} — 파괴 실행 "시점" 스냅샷

vars == <<uSet, retired, dStatus, dSnap, eStatus, eKilledByD, dKilledByE, executed>>

Init ==
    /\ uSet = {} /\ retired = {}
    /\ dStatus = [c \in Calls |-> "NONE"]
    /\ dSnap = [c \in Calls |-> {}]
    /\ eStatus = [c \in Calls |-> "NONE"]
    /\ eKilledByD = FALSE /\ dKilledByE = FALSE
    /\ executed = {}

(***************************************************************************)
(* U-집합 동역학 — 승인~소비 사이에 끼어들 수 있는 두 전이 (TOCTOU의 심장) *)
(***************************************************************************)

\* <-> recordToolResult(비신뢰 소스) → createTaintNode(U 태그). 새 read는 항상
\*     새 tn_uuid이므로 retired 재사용 금지 — 집합이 과거 값으로 못 돌아간다.
ReadUntrusted(u) ==
    /\ u \notin uSet /\ u \notin retired
    /\ uSet' = uSet \cup {u}
    /\ UNCHANGED <<retired, dStatus, dSnap, eStatus, eKilledByD, dKilledByE, executed>>

\* <-> attemptSanitization(STRUCTURED_EXTRACTION) → declassifyNodeTag(U 제거).
\*     언제든 일어날 수 있는 비결정 = 과근사(정화 검증 통과 여부는 단위 테스트 소관).
DeclassifyU(u) ==
    /\ u \in uSet
    /\ uSet' = uSet \ {u}
    /\ retired' = retired \cup {u}
    /\ UNCHANGED <<dStatus, dSnap, eStatus, eKilledByD, dKilledByE, executed>>

(***************************************************************************)
(* 파괴 게이트 — destructivePolicy:"hitl"의 차단·제안·승인·소비 수명주기   *)
(***************************************************************************)

\* <-> computeDestructiveDecision 차단 분기의 offerOverride(gate="destructive").
\*     guard의 uSet # {} = "세션이 비신뢰에 노출됨 → 차단" (차단 시에만 제안).
\*     OFFERED인데 지문(스냅샷)이 달라졌으면 낡은 제안을 접고 재발급 —
\*     코드의 SUPERSEDED 봉인+신규 발급을 한 전이로 접음 (approvalId 갱신 추상화).
DOffer(c) ==
    /\ uSet # {}
    /\ \/ dStatus[c] \in {"NONE", "REJECTED", "USED", "SUPERSEDED", "STALE"}
       \/ (dStatus[c] = "OFFERED" /\ dSnap[c] # uSet)
    /\ dStatus' = [dStatus EXCEPT ![c] = "OFFERED"]
    /\ dSnap' = [dSnap EXCEPT ![c] = uSet]    \* ★제안 시점 U-집합 스냅샷 저장
    /\ UNCHANGED <<uSet, retired, eStatus, eKilledByD, dKilledByE, executed>>

\* <-> requestApproval(접음) + resolveApproval. 사람의 결정은 비결정.
DApprove(c) ==
    /\ dStatus[c] = "OFFERED"
    /\ dStatus' = [dStatus EXCEPT ![c] = "APPROVED"]
    /\ UNCHANGED <<uSet, retired, dSnap, eStatus, eKilledByD, dKilledByE, executed>>

DReject(c) ==
    /\ dStatus[c] = "OFFERED"
    /\ dStatus' = [dStatus EXCEPT ![c] = "REJECTED"]
    /\ UNCHANGED <<uSet, retired, dSnap, eStatus, eKilledByD, dKilledByE, executed>>

\* ★ <-> consumeApprovalIfMatching(gate="destructive")의 일치 분기: 소비 시점
\*    U-집합이 제안 시점 스냅샷과 정확히 같을 때만 1회 소비하고 실행.
\*    uSet = dSnap[c] 한 줄이 TOCTOU 재검증 — 승인 후 ReadUntrusted(증가)든
\*    DeclassifyU(감소)든 끼어들면 이 guard가 꺼진다.
DConsume(c) ==
    /\ dStatus[c] = "APPROVED"
    /\ uSet = dSnap[c]
    /\ dStatus' = [dStatus EXCEPT ![c] = "USED"]    \* single-use
    /\ executed' = executed \cup
         {[call |-> c, uAtExit |-> uSet, snapAtOffer |-> dSnap[c], via |-> "OVERRIDE"]}
    /\ UNCHANGED <<uSet, retired, dSnap, eStatus, eKilledByD, dKilledByE>>

\* <-> 불일치 분기: 낡은 승인 영구 무효(used=true, OVERRIDE_STALE) + 차단 유지
\*    (executed 불변 — 아무것도 실행되지 않는다). USED로 접음(위 단순화 주석).
\*    이후에도 여전히 차단 상황이면 DOffer가 재제안 — 정상 HITL 흐름은 유지.
DConsumeStale(c) ==
    /\ dStatus[c] = "APPROVED"
    /\ uSet # dSnap[c]
    /\ dStatus' = [dStatus EXCEPT ![c] = "USED"]
    /\ UNCHANGED <<uSet, retired, dSnap, eStatus, eKilledByD, dKilledByE, executed>>

\* <-> 게이트 통과 경로: 세션에 살아있는 U가 없으면(사용자 직접 지시 삭제,
\*    또는 정화 완료 후) 승인 없이 실행된다. 실행 시점 스냅샷 기록.
DExecNoU(c) ==
    /\ uSet = {}
    /\ executed' = executed \cup
         {[call |-> c, uAtExit |-> {}, snapAtOffer |-> {}, via |-> "NO_U"]}
    /\ UNCHANGED <<uSet, retired, dStatus, dSnap, eStatus, eKilledByD, dKilledByE>>

(***************************************************************************)
(* 유출 게이트 — 수명주기만 (taint guard 없는 과근사).                     *)
(* 존재 이유: 두 게이트가 offers 저장소를 공유할 때의 교차 간섭을 관측.    *)
(***************************************************************************)

EOffer(c) ==
    /\ eStatus[c] \in {"NONE", "REJECTED", "USED", "SUPERSEDED", "STALE"}
    /\ eStatus' = [eStatus EXCEPT ![c] = "OFFERED"]
    /\ UNCHANGED <<uSet, retired, dStatus, dSnap, eKilledByD, dKilledByE, executed>>

EApprove(c) ==
    /\ eStatus[c] = "OFFERED"
    /\ eStatus' = [eStatus EXCEPT ![c] = "APPROVED"]
    /\ UNCHANGED <<uSet, retired, dStatus, dSnap, eKilledByD, dKilledByE, executed>>

EReject(c) ==
    /\ eStatus[c] = "OFFERED"
    /\ eStatus' = [eStatus EXCEPT ![c] = "REJECTED"]
    /\ UNCHANGED <<uSet, retired, dStatus, dSnap, eKilledByD, dKilledByE, executed>>

EConsume(c) ==
    /\ eStatus[c] = "APPROVED"
    /\ eStatus' = [eStatus EXCEPT ![c] = "USED"]
    /\ UNCHANGED <<uSet, retired, dStatus, dSnap, eKilledByD, dKilledByE, executed>>

(***************************************************************************)
(* ★ 교차-게이트 소각 전이 4종 — naive 공유 키(SharedKeys=TRUE)에서만 활성. *)
(*                                                                         *)
(* <-> 수정 전 지문 fingerprintOf = sha256(sessionId|toolName|args)에 gate  *)
(* 가 없으면: 같은 호출(지문 동일)에 두 게이트가 각자 offer/consume을 할   *)
(* 때 서로의 offer가 스캔에 걸린다. 계보 지문(lineageFingerprint)은 증거   *)
(* "타입"이 달라(값-계보 evidence vs U-집합 스냅샷) 항상 불일치이므로 —    *)
(*  - offerOverride: 상대 게이트의 진행 중(OFFERED) 제안을 SUPERSEDED 봉인 *)
(*  - consumeApprovalIfMatching: 상대 게이트의 APPROVED 승인을 지문 불일치 *)
(*    로 used=true(STALE) 영구 소각 — 정당한 승인이 실행 없이 죽는다.      *)
(* 수정판(FALSE)은 지문에 gate가 들어가 상대 offer가 아예 스캔에 안 걸림   *)
(* = 이 전이들이 비활성 → GateIsolation이 전 상태에서 성립.                *)
(***************************************************************************)

CrossSupersedeByD(c) ==    \* 파괴 게이트의 offer가 유출 제안을 봉인
    /\ SharedKeys
    /\ uSet # {}                       \* 파괴 게이트가 제안을 낼 상황(차단 중)일 때
    /\ eStatus[c] = "OFFERED"
    /\ eStatus' = [eStatus EXCEPT ![c] = "SUPERSEDED"]
    /\ eKilledByD' = TRUE
    /\ UNCHANGED <<uSet, retired, dStatus, dSnap, dKilledByE, executed>>

CrossStaleByD(c) ==        \* 파괴 게이트의 소비 스캔이 유출 승인을 소각
    /\ SharedKeys
    /\ uSet # {}
    /\ eStatus[c] = "APPROVED"
    /\ eStatus' = [eStatus EXCEPT ![c] = "STALE"]
    /\ eKilledByD' = TRUE
    /\ UNCHANGED <<uSet, retired, dStatus, dSnap, dKilledByE, executed>>

CrossSupersedeByE(c) ==    \* 유출 게이트의 offer가 파괴 제안을 봉인 (대칭)
    /\ SharedKeys
    /\ dStatus[c] = "OFFERED"
    /\ dStatus' = [dStatus EXCEPT ![c] = "SUPERSEDED"]
    /\ dKilledByE' = TRUE
    /\ UNCHANGED <<uSet, retired, dSnap, eStatus, eKilledByD, executed>>

CrossStaleByE(c) ==        \* 유출 게이트의 소비 스캔이 파괴 승인을 소각 (대칭)
    /\ SharedKeys
    /\ dStatus[c] = "APPROVED"
    /\ dStatus' = [dStatus EXCEPT ![c] = "STALE"]
    /\ dKilledByE' = TRUE
    /\ UNCHANGED <<uSet, retired, dSnap, eStatus, eKilledByD, executed>>

Next ==
    \/ \E u \in UNodes : ReadUntrusted(u) \/ DeclassifyU(u)
    \/ \E c \in Calls :
         \/ DOffer(c) \/ DApprove(c) \/ DReject(c)
         \/ DConsume(c) \/ DConsumeStale(c) \/ DExecNoU(c)
         \/ EOffer(c) \/ EApprove(c) \/ EReject(c) \/ EConsume(c)
         \/ CrossSupersedeByD(c) \/ CrossStaleByD(c)
         \/ CrossSupersedeByE(c) \/ CrossStaleByE(c)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* 불변식                                                                  *)
(***************************************************************************)

TypeOK ==
    /\ uSet \subseteq UNodes
    /\ retired \subseteq UNodes
    /\ uSet \cap retired = {}
    /\ dStatus \in [Calls -> Status]
    /\ dSnap \in [Calls -> SUBSET UNodes]
    /\ eStatus \in [Calls -> Status]
    /\ eKilledByD \in BOOLEAN /\ dKilledByE \in BOOLEAN
    /\ \A e \in executed :
         /\ e.call \in Calls
         /\ e.uAtExit \subseteq UNodes
         /\ e.snapAtOffer \subseteq UNodes
         /\ e.via \in {"NO_U", "OVERRIDE"}

\* ★ 핵심 안전 속성 1: "비신뢰가 유발했을 수 있는 파괴"는 사람 승인 없이
\*   절대 실행되지 않는다 — U-오염 상태의 실행은 전부 OVERRIDE 경유.
\*   (역방향 보장도 포함: NO_U 실행은 반드시 U-공집합 시점 = 사용자 직접
\*   지시 삭제는 승인 없이 통과 — 과차단 아님을 같은 불변식이 진술.)
DestructiveSafety ==
    \A e \in executed :
        /\ (e.via = "NO_U") => (e.uAtExit = {})
        /\ (e.uAtExit # {}) => (e.via = "OVERRIDE")

\* ★ 핵심 안전 속성 2 (TOCTOU freshness): 승인 경유 실행은 "사람이 승인한
\*   바로 그 U-그림"에서만 일어난다 — 실행 시점 U-집합 = 제안 시점 스냅샷.
\*   승인~소비 사이에 U가 늘거나(새 비신뢰 read) 줄면(정화) 실행 불가.
\*   id 신선성(retired) 덕에 "달라졌다 되돌아온 집합"은 존재 자체가 불가능
\*   — 한 번이라도 다른 상태를 거친 승인은 재사용 불가(코드 used=true)와 동치.
ApprovalFreshness ==
    \A e \in executed :
        (e.via = "OVERRIDE") => (e.uAtExit = e.snapAtOffer /\ e.snapAtOffer # {})

\* ★ 핵심 안전 속성 3: 게이트 격리 — 파괴 게이트의 어떤 행동도 유출 offer를
\*   봉인·소각하지 못하고, 역방향도 마찬가지. SharedKeys=FALSE(수정판)에서
\*   전 상태 성립 = TaintHITL.tla의 유출 게이트 전제(자기 offers를 자기만
\*   만진다)가 파괴 게이트 추가 후에도 유지된다는 근거.
\*   SharedKeys=TRUE 변형에서는 3~4스텝 반례로 깨진다 (버그 실재 증명).
GateIsolation ==
    /\ eKilledByD = FALSE
    /\ dKilledByE = FALSE

\* 지문 저장 건전성: 진행 중(OFFERED/APPROVED)인 파괴 제안의 스냅샷은 비어있지
\* 않다 — 제안은 차단(U 존재) 시에만 나므로 "빈 그림의 승인"은 존재할 수 없다.
SnapConsistency ==
    \A c \in Calls :
        dStatus[c] \in {"OFFERED", "APPROVED"} => dSnap[c] # {}

(***************************************************************************)
(* 비공허성 witness용 반전 불변식 — 본 cfg에는 넣지 않는다. 스크래치 cfg에  *)
(* 하나씩 넣어 TLC가 내놓는 "반례"가 곧 정상 동작 witness다 (README 관례):  *)
(*  - NoOverrideExit 반례 = 승인 흐름이 실제로 작동한다                     *)
(*    (Read → DOffer → DApprove → DConsume, U-집합 무변화).                *)
(*  - NoNoUExit 반례 = 사용자 직접 지시 삭제가 승인 없이 통과한다           *)
(*    (DExecNoU 1스텝) — "무조건 막는 게이트"가 아님의 형식적 확인.         *)
(***************************************************************************)

NoOverrideExit == \A e \in executed : e.via # "OVERRIDE"

NoNoUExit == \A e \in executed : e.via # "NO_U"

==============================================================================
