------------------------ MODULE TaintDestructiveHITL ------------------------
(***************************************************************************)
(* 파괴적 액션 게이트("비신뢰가 유발한 파괴"만 차단) + HITL 오버라이드의    *)
(* 안전성 모델. ★F1 수정 반영판: 게이트 U축을 "살아있는 U 집합"이 아니라   *)
(* **세션 노출이력(exposure, monotone)**으로 판정한다.                      *)
(*                                                                         *)
(* ★ F1 수정 (헌팅에서 발견한 정화 세탁 미탐 — P6):                         *)
(*   이전 모델은 DExecNoU(승인 없는 삭제)를 `uSet = {}`(살아있는 U 없음)에   *)
(*   활성화했다. 그런데 DeclassifyU(정화)가 uSet을 비울 수 있으므로, 공격자 *)
(*   통제 콘텐츠를 정화해 uSet을 비운 뒤 승인 없이 삭제가 실행됐다(P6).     *)
(*   즉 이전 DestructiveSafety("NO_U는 uAtExit={}이면 안전")는 F1을 안전으로 *)
(*   "잘못" 모델링하고 있었다.                                              *)
(*                                                                         *)
(*   수정: exposure(어떤 ReadUntrusted든 TRUE, 이후 절대 FALSE 안 됨)를 두고 *)
(*   - DExecNoU 는 ~exposure 일 때만 (한 번도 비신뢰에 노출 안 된 세션 =    *)
(*     사용자 직접 지시 삭제)                                               *)
(*   - DOffer(HITL 제안)는 exposure 일 때 — 정화로 uSet을 비워도 exposure가 *)
(*     살아 게이트가 닫힌 채 HITL 승인만 해제한다.                          *)
(*   - DeclassifyU 는 uSet만 줄이고 exposure는 못 끈다 (monotone).           *)
(*                                                                         *)
(* TaintHITL.tla가 커버 못 하는 새 축 3가지는 그대로 (판정 술어·변이        *)
(* 알파벳·2게이트 교차). exposure 도입 후에도 GateIsolation은 유지된다.     *)
(*                                                                         *)
(* 단순화 (기존과 동일): id 신선성(retired), 유출 게이트는 수명주기만,      *)
(* PENDING은 OFFERED에 접음, SUPERSEDED/STALE은 교차 소각 전용.             *)
(*                                                                         *)
(* ★ 정직성(GateIsolation·F1): SharedKeys=FALSE(수정판)에서 교차 전이 4종이 *)
(* 비활성. SharedKeys=TRUE 변형은 4스텝 반례(교차 봉인). 그리고 DExecNoU를  *)
(* 옛 `uSet={}`로 되돌린 mutation은 DestructiveSafety를 짧은 반례로 깨       *)
(* (정화 후 승인 없는 삭제 = F1) — 수정의 형식적 근거.                      *)
(***************************************************************************)
EXTENDS FiniteSets

CONSTANTS
    UNodes,     \* 비신뢰(U) 보유자 노드 id 풀 (상태 폭발 관리를 위해 기본 2개)
    Calls,      \* 파괴적 도구 호출 지문(sessionId|toolName|args) 식별자
    SharedKeys  \* FALSE = 수정판(gate 판별자 지문), TRUE = naive 공유 키(버그 재현)

ASSUME SharedKeys \in BOOLEAN

Status == {"NONE", "OFFERED", "APPROVED", "REJECTED", "USED", "SUPERSEDED", "STALE"}

VARIABLES
    uSet,       \* 살아있는 U-보유자 집합        <-> sessionHasLiveTag=true인 노드들
    retired,    \* 정화돼 은퇴한 id (재사용 불가) <-> declassify된 노드 (id는 소멸 안 함)
    exposure,   \* BOOLEAN 세션 비신뢰 노출이력   <-> ★ untrustedExposure (grow-only)
    dStatus,    \* [Calls -> Status] 파괴 게이트 offer 상태
    dSnap,      \* [Calls -> SUBSET UNodes]      <-> 파괴 offer의 U-집합 스냅샷 지문
    eStatus,    \* [Calls -> Status] 유출 게이트 offer 상태 (수명주기만 — 과근사)
    eKilledByD, \* 파괴 게이트 행동이 유출 offer를 SUPERSEDE/소각했는가 (격리 위반 관측자)
    dKilledByE, \* 유출 게이트 행동이 파괴 offer를 SUPERSEDE/소각했는가 (대칭)
    executed    \* {[call, exposureAtExit, snapAtOffer, uAtExit, via]} — 실행 "시점" 스냅샷

vars == <<uSet, retired, exposure, dStatus, dSnap, eStatus, eKilledByD, dKilledByE, executed>>

Init ==
    /\ uSet = {} /\ retired = {} /\ exposure = FALSE
    /\ dStatus = [c \in Calls |-> "NONE"]
    /\ dSnap = [c \in Calls |-> {}]
    /\ eStatus = [c \in Calls |-> "NONE"]
    /\ eKilledByD = FALSE /\ dKilledByE = FALSE
    /\ executed = {}

(***************************************************************************)
(* U-집합 동역학 + 노출이력                                                 *)
(***************************************************************************)

\* <-> recordToolResult(비신뢰 소스) → createTaintNode(U 태그) + exposure 세팅.
\*     새 read는 항상 새 tn_uuid이므로 retired 재사용 금지. exposure는 여기서만
\*     켜지고(grow-only) 이후 어떤 전이도 끄지 않는다.
ReadUntrusted(u) ==
    /\ u \notin uSet /\ u \notin retired
    /\ uSet' = uSet \cup {u}
    /\ exposure' = TRUE
    /\ UNCHANGED <<retired, dStatus, dSnap, eStatus, eKilledByD, dKilledByE, executed>>

\* <-> attemptSanitization(STRUCTURED_EXTRACTION) → declassifyNodeTag(U 제거).
\*     ★ uSet만 줄인다. exposure는 UNCHANGED — 정화는 그 값을 안전하게 만들 뿐
\*     "세션이 비신뢰에 노출됐던 사실"은 못 되돌린다 (F1 수정의 핵심).
DeclassifyU(u) ==
    /\ u \in uSet
    /\ uSet' = uSet \ {u}
    /\ retired' = retired \cup {u}
    /\ UNCHANGED <<exposure, dStatus, dSnap, eStatus, eKilledByD, dKilledByE, executed>>

(***************************************************************************)
(* 파괴 게이트 — destructivePolicy:"hitl"의 차단·제안·승인·소비 수명주기   *)
(***************************************************************************)

\* <-> computeDestructiveDecision 차단 분기의 offerOverride(gate="destructive").
\*     ★ guard exposure = "세션이 비신뢰에 노출된 적 있음 → 차단" (정화로 uSet을
\*     비워도 exposure가 살아 게이트가 열리지 않는다). dSnap은 여전히 live uSet을
\*     스냅샷 — TOCTOU 재검증용(승인~소비 사이 uSet 변화 감지).
DOffer(c) ==
    /\ exposure
    /\ \/ dStatus[c] \in {"NONE", "REJECTED", "USED", "SUPERSEDED", "STALE"}
       \/ (dStatus[c] = "OFFERED" /\ dSnap[c] # uSet)
    /\ dStatus' = [dStatus EXCEPT ![c] = "OFFERED"]
    /\ dSnap' = [dSnap EXCEPT ![c] = uSet]
    /\ UNCHANGED <<uSet, retired, exposure, eStatus, eKilledByD, dKilledByE, executed>>

DApprove(c) ==
    /\ dStatus[c] = "OFFERED"
    /\ dStatus' = [dStatus EXCEPT ![c] = "APPROVED"]
    /\ UNCHANGED <<uSet, retired, exposure, dSnap, eStatus, eKilledByD, dKilledByE, executed>>

DReject(c) ==
    /\ dStatus[c] = "OFFERED"
    /\ dStatus' = [dStatus EXCEPT ![c] = "REJECTED"]
    /\ UNCHANGED <<uSet, retired, exposure, dSnap, eStatus, eKilledByD, dKilledByE, executed>>

\* ★ <-> consumeApprovalIfMatching(gate="destructive")의 일치 분기: 소비 시점
\*    U-집합이 제안 시점 스냅샷과 정확히 같을 때만 1회 소비하고 실행.
\*    exposure는 DOffer 이후 monotone하게 TRUE이므로 exposureAtExit=TRUE.
DConsume(c) ==
    /\ dStatus[c] = "APPROVED"
    /\ uSet = dSnap[c]
    /\ dStatus' = [dStatus EXCEPT ![c] = "USED"]    \* single-use
    /\ executed' = executed \cup
         {[call |-> c, exposureAtExit |-> exposure, snapAtOffer |-> dSnap[c],
           uAtExit |-> uSet, via |-> "OVERRIDE"]}
    /\ UNCHANGED <<uSet, retired, exposure, dSnap, eStatus, eKilledByD, dKilledByE>>

DConsumeStale(c) ==
    /\ dStatus[c] = "APPROVED"
    /\ uSet # dSnap[c]
    /\ dStatus' = [dStatus EXCEPT ![c] = "USED"]
    /\ UNCHANGED <<uSet, retired, exposure, dSnap, eStatus, eKilledByD, dKilledByE, executed>>

\* ★ <-> 게이트 통과 경로: 세션이 한 번도 비신뢰에 노출되지 않았을 때만(사용자
\*    직접 지시 삭제) 승인 없이 실행. F1 수정: guard가 `uSet={}`(정화로 우회 가능)
\*    이 아니라 `~exposure`(정화로 못 우회). exposureAtExit=FALSE.
DExecNoU(c) ==
    /\ ~exposure
    /\ executed' = executed \cup
         {[call |-> c, exposureAtExit |-> exposure, snapAtOffer |-> {},
           uAtExit |-> uSet, via |-> "NO_U"]}
    /\ UNCHANGED <<uSet, retired, exposure, dStatus, dSnap, eStatus, eKilledByD, dKilledByE>>

(***************************************************************************)
(* 유출 게이트 — 수명주기만 (taint guard 없는 과근사).                     *)
(* 존재 이유: 두 게이트가 offers 저장소를 공유할 때의 교차 간섭을 관측.    *)
(***************************************************************************)

EOffer(c) ==
    /\ eStatus[c] \in {"NONE", "REJECTED", "USED", "SUPERSEDED", "STALE"}
    /\ eStatus' = [eStatus EXCEPT ![c] = "OFFERED"]
    /\ UNCHANGED <<uSet, retired, exposure, dStatus, dSnap, eKilledByD, dKilledByE, executed>>

EApprove(c) ==
    /\ eStatus[c] = "OFFERED"
    /\ eStatus' = [eStatus EXCEPT ![c] = "APPROVED"]
    /\ UNCHANGED <<uSet, retired, exposure, dStatus, dSnap, eKilledByD, dKilledByE, executed>>

EReject(c) ==
    /\ eStatus[c] = "OFFERED"
    /\ eStatus' = [eStatus EXCEPT ![c] = "REJECTED"]
    /\ UNCHANGED <<uSet, retired, exposure, dStatus, dSnap, eKilledByD, dKilledByE, executed>>

EConsume(c) ==
    /\ eStatus[c] = "APPROVED"
    /\ eStatus' = [eStatus EXCEPT ![c] = "USED"]
    /\ UNCHANGED <<uSet, retired, exposure, dStatus, dSnap, eKilledByD, dKilledByE, executed>>

(***************************************************************************)
(* ★ 교차-게이트 소각 전이 4종 — naive 공유 키(SharedKeys=TRUE)에서만 활성. *)
(* 조건 exposure = "파괴 게이트가 활성(차단/스캔) 상태" (F1 수정 후 판정축). *)
(***************************************************************************)

CrossSupersedeByD(c) ==    \* 파괴 게이트의 offer가 유출 제안을 봉인
    /\ SharedKeys
    /\ exposure
    /\ eStatus[c] = "OFFERED"
    /\ eStatus' = [eStatus EXCEPT ![c] = "SUPERSEDED"]
    /\ eKilledByD' = TRUE
    /\ UNCHANGED <<uSet, retired, exposure, dStatus, dSnap, dKilledByE, executed>>

CrossStaleByD(c) ==        \* 파괴 게이트의 소비 스캔이 유출 승인을 소각
    /\ SharedKeys
    /\ exposure
    /\ eStatus[c] = "APPROVED"
    /\ eStatus' = [eStatus EXCEPT ![c] = "STALE"]
    /\ eKilledByD' = TRUE
    /\ UNCHANGED <<uSet, retired, exposure, dStatus, dSnap, dKilledByE, executed>>

CrossSupersedeByE(c) ==    \* 유출 게이트의 offer가 파괴 제안을 봉인 (대칭)
    /\ SharedKeys
    /\ dStatus[c] = "OFFERED"
    /\ dStatus' = [dStatus EXCEPT ![c] = "SUPERSEDED"]
    /\ dKilledByE' = TRUE
    /\ UNCHANGED <<uSet, retired, exposure, dSnap, eStatus, eKilledByD, executed>>

CrossStaleByE(c) ==        \* 유출 게이트의 소비 스캔이 파괴 승인을 소각 (대칭)
    /\ SharedKeys
    /\ dStatus[c] = "APPROVED"
    /\ dStatus' = [dStatus EXCEPT ![c] = "STALE"]
    /\ dKilledByE' = TRUE
    /\ UNCHANGED <<uSet, retired, exposure, dSnap, eStatus, eKilledByD, executed>>

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
    /\ exposure \in BOOLEAN
    /\ dStatus \in [Calls -> Status]
    /\ dSnap \in [Calls -> SUBSET UNodes]
    /\ eStatus \in [Calls -> Status]
    /\ eKilledByD \in BOOLEAN /\ dKilledByE \in BOOLEAN
    /\ \A e \in executed :
         /\ e.call \in Calls
         /\ e.exposureAtExit \in BOOLEAN
         /\ e.snapAtOffer \subseteq UNodes
         /\ e.uAtExit \subseteq UNodes
         /\ e.via \in {"NO_U", "OVERRIDE"}

\* ★ 핵심 안전 속성 1 (F1 수정 반영): "비신뢰가 유발했을 수 있는 파괴"는 사람
\*   승인 없이 절대 실행되지 않는다 — 노출된 세션의 실행은 전부 OVERRIDE 경유.
\*   역방향(과차단 아님): NO_U 실행은 반드시 노출이력 없는 세션 = 사용자 직접
\*   지시 삭제는 승인 없이 통과. ★이전판은 "uAtExit={}"였고, 정화로 uSet을 비운
\*   NO_U 실행을 안전으로 오판했다(F1). 이제 exposureAtExit로 판정한다.
DestructiveSafety ==
    \A e \in executed :
        /\ (e.via = "NO_U") => (~e.exposureAtExit)
        /\ (e.exposureAtExit) => (e.via = "OVERRIDE")

\* ★ 핵심 안전 속성 2 (TOCTOU freshness): 승인 경유 실행은 "사람이 승인한 바로
\*   그 U-그림"에서만 — 실행 시점 uSet = 제안 시점 스냅샷. 승인~소비 사이 U가
\*   늘거나(새 read) 줄면(정화) 실행 불가. (exposure 도입 후 snapAtOffer가 {}일
\*   수 있으므로 — 노출됐지만 live U가 정화로 빈 채 제안된 경우 — 비어있음 요건은
\*   뺀다. 안전성은 exposureAtExit로 DestructiveSafety가 담보한다.)
ApprovalFreshness ==
    \A e \in executed :
        (e.via = "OVERRIDE") => (e.uAtExit = e.snapAtOffer)

\* ★ 핵심 안전 속성 3: 게이트 격리 — 파괴 게이트의 어떤 행동도 유출 offer를
\*   봉인·소각하지 못하고, 역방향도 마찬가지 (SharedKeys=FALSE에서 전 상태 성립).
GateIsolation ==
    /\ eKilledByD = FALSE
    /\ dKilledByE = FALSE

\* ★ 노출이력 단조성: exposure는 한 번 TRUE가 되면 절대 FALSE로 안 돌아간다
\*   (정화 DeclassifyU 포함 어느 전이도 못 끔). F1 세탁 방지의 형식적 근거.
ExposureMonotone == [][exposure => exposure']_vars

\* 지문 저장 건전성: 진행 중(OFFERED/APPROVED)인 파괴 제안이 있으면 세션은
\* 반드시 노출된 상태다 (제안은 exposure 시에만 나므로). ★이전판은 "dSnap#{}"
\* 였으나, exposure 판정 후엔 정화로 live U가 빈 채 제안될 수 있어 exposure로 바꾼다.
SnapConsistency ==
    \A c \in Calls :
        dStatus[c] \in {"OFFERED", "APPROVED"} => exposure

(***************************************************************************)
(* 비공허성 witness용 반전 불변식 — 본 cfg에는 넣지 않는다. 스크래치 cfg에  *)
(* 하나씩 넣어 TLC가 내놓는 "반례"가 곧 정상 동작 witness다 (README 관례):  *)
(*  - NoOverrideExit 반례 = 승인 흐름이 실제로 작동한다.                    *)
(*  - NoNoUExit 반례 = 사용자 직접 지시 삭제가 승인 없이 통과한다           *)
(*    (노출 전 DExecNoU) — "무조건 막는 게이트"가 아님의 형식적 확인.       *)
(***************************************************************************)

NoOverrideExit == \A e \in executed : e.via # "OVERRIDE"

NoNoUExit == \A e \in executed : e.via # "NO_U"

==============================================================================
