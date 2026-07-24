# policy-engine 형식검증 (TLA+ / TLC)

값 단위 taint 계보의 핵심 안전 속성을 TLC 모델 체커로 전수 탐색해 증명한다.

| 모듈 | 무엇의 모델인가 |
|---|---|
| `TaintSafety.tla` | 세션 단위 boolean 판정(toy) — 1주차 최소 모델 |
| `TaintLineage.tla` | **값 단위 계보 판정(real)** — snapshot 전파 + 비대칭 정화 + 차단 규칙 |
| `TaintLineageLive.tla` | **live 전파 확장** — addNodeTags+cascadeDown(사후 오염·하향 전파) + sink 재통과 |
| `TaintHITL.tla` | **HITL 오버라이드 — TOCTOU 발견→수정 검증** ★ 1단계: 버그 재현(반례 5스텝) → 2단계: 소비 시점 계보 지문 대조 추가 후 위반 0 |
| `TaintPruning.tla` | **가지치기 상태-점별 판정 보존(PruneSafety)** — 수정 전 의미론에서도 성립 (보존 기록) |
| `TaintPruningCommute.tla` | **가지치기 교환성 — 발견→수정 검증** ★ 1단계: 반례 5스텝(git 이력) → 2단계: 재오염 가능 묘비 반영 후 위반 0 |
| `TaintDestructiveHITL.tla` | **파괴적 액션 게이트 + HITL** — "비신뢰가 유발한 파괴"만 차단. 불변식 3종 위반 0 (구현보다 모델 선행 — model-first) |

## 증명된 속성 (TaintLineage) — ★F1 수정 반영판 (비대칭 + 노출이력)

> **ExfilSafety**: 어떤 실행 순서로도, 세션이 비신뢰에 노출된 상태(exposure)에서
> 민감(SENSITIVE) 값이 sink에 도달하는 것은 불가능하다.

★ 이전 모델은 U를 S와 대칭인 노드 태그로 두고 `Declassify`로 제거 가능하게 했다 —
이것이 정확히 헌팅에서 발견한 **F1(정화 세탁 미탐)의 형식적 뿌리**였다: 실제 코드의
비대칭 위협 모델은 U축을 "세션 존재"로 보는데, 정화가 그 U 노드를 떼면 세션 U축이
통째로 꺼져(sessionHasLiveTag=false) 정화와 무관한 유출(C1)·삭제(P6)가 열렸다.

수정: U축을 노드 태그가 아니라 **세션 노출이력(exposure, grow-only)**으로 모델링한다.
- `exposure`: 어떤 노드든 U를 획득하면 TRUE, 이후 절대 FALSE 안 됨.
- `Declassify`는 노드의 값-계보 태그(S)만 떼고 `exposure`는 UNCHANGED (정화 불변).
- 차단 = `valueSensitive(S ∈ tags[n]) ∧ exposure`. S를 토큰화하면 통과(RE35),
  U-only는 S가 없어 통과(RE36), "U 정화 후 무관 S 전송"(C1)만 차단.

**양립 논증** (세탁방지 vs 과차단방지가 서로 다른 축이라 안 충돌): 세탁 방지는
`ExposureMonotone`(정화가 U축을 못 끔), 과차단 방지는 차단식의 `valueSensitive ∧`
항(S를 정화하면 통과) — 두 목표가 각각 다른 연산자 항에 걸려 상호 간섭이 없다.

- 검증 결과 (TaintLineage, 수정판): 노드 4개 기준 **42,490,597 상태 생성 /
  7,641,457 고유 상태 전수 탐색(깊이 19), 불변식 4종(TypeOK / ★ExfilSafety /
  ParentsExist / Unborn) + 속성 ExposureMonotone 위반 0** (TLC 2026.07, 3분 17초).
- ★ 버그 재현(F1 실재 증명): `ReachSink` guard를 옛 대칭판
  `~(S ∈ tags[n] ∧ U ∈ tags[n])`로 되돌린 변형에서 **ExfilSafety가 반례로 깨짐** —
  U 노드를 declassify한 뒤 S 값이 노출 세션을 통과(C1)한다. 수정판(exposure)에서는
  그 통과가 비활성.
- 비공허성 witness 2종(원본 무손상): `NoCleanSExit` 반례 = 노출 전 S 정상 통과
  (RE35류, 과차단 아님); `NoExposedExit` 반례 = 노출 세션에서 S 없는 값 통과(RE36류).

### (참고) 이전 대칭 SinkSafety의 위상

수정 전 `SinkSafety(~Trifecta(tagsAtExit))`는 "S+U 노드가 함께 sink 도달 불가"를
증명했다. 새 `ExfilSafety`는 그 조건을 **포함하며 더 강하다**: S+U 노드는 U 획득으로
exposure를 켜므로 (S ∧ exposure)로 여전히 차단되고, 추가로 "U를 정화로 떼도 S 유출
차단"(C1)까지 막는다. 즉 수정은 기존 안전성의 순확장(regression 없음)이다.

## live 전파 확장 (TaintLineageLive)

snapshot 모델의 "생성 후 태그 불증가" 가정을 깨는 live 전파
(`addNodeTags` + `cascadeDown`, `propagationMode: "live"`)까지 포함해 같은 속성을 증명:

- **AddTag(n, t) 전이 추가** — n과 n의 모든 "자손"에게 t를 하향 전파.
  자손 계산(DescendantsOf)이 부모→자식 방향만 따라가므로 역류(조상 오염)는
  수식상 표현 자체가 불가능 (cascadeDown이 childIndex만 따라가는 코드와 1:1 대응).
- **"노드당 sink 1회 통과" 단순화 제거** — 태그가 늘 수 있으므로 재통과를 허용해야
  "깨끗하게 통과 → 사후 오염 → 재통과"라는 live 고유 위험 시나리오가 탐색된다.
  exfiltrated가 통과 시점 태그 스냅샷을 기록하므로 각 통과는 독립 판정.
- 보조 불변식 `GrowthReExitSafety`: "태그가 늘어난 재통과가 트라이펙타면 위반" —
  태그 증가는 AddTag로만 가능하므로 이 불변식의 반례에는 반드시 AddTag가 등장한다.
- 검증 결과: 노드 3개 기준 **6,958,357 상태 생성 / 828,513 고유 상태 전수 탐색
  (깊이 22), 위반 0** (18초, 불변식 5종).
- 노드 4개는 20분 타임박스 초과로 미채택 (AddTag×재통과로 상태 공간이 노드 수에
  지수적). 3개로 충분한 근거: 새로 추가된 메커니즘(다단 하향 전파)은 3-노드
  체인(조상→중간→자손)에서 이미 온전히 발현되며, snapshot 공통 부분은
  TaintLineage.tla가 4-노드로 검증했다.
- sanity check 2종 (guard 제거 변형, 원본 무손상):
  1. SinkSafety — 3스텝 반례 즉시 발생.
  2. GrowthReExitSafety — **5스텝 반례가 정확히 live 고유 경로를 시연**:
     `생성{SENSITIVE} → 통과({S} 기록) → AddTag(UNTRUSTED) → 재통과(트라이펙타)`.
     guard가 있는 본 모델에서는 이 재통과가 비활성 = 차단된다.

## HITL 오버라이드 TOCTOU — 발견(1단계) → 수정 + 재증명(2단계) (TaintHITL)

두 단계로 진행했다: **1단계**는 승인 재검증 누락(TOCTOU)을 그대로 모델링해
TLC가 위반 반례를 내놓음을 확인 — "버그가 설계 수준에서 실재한다"는 증거.
**2단계**는 코드를 고치고(소비 시점 계보 지문 대조) 모델에도 같은 재검증
guard를 넣어 **HITLSafety 위반 0을 전 상태 탐색으로 재증명** + 비공허성
witness("정상 weak 승인은 여전히 통과")까지 확인.

### 문제 (1단계에서 발견한 코드 근거)

- 당시 `consumeApprovalIfMatching`(hitl.ts)은 지문 `sha256(sessionId|toolName|args)`
  일치 + APPROVED + 미사용, 이 셋만 보고 승인을 소비했다. **소비 직전에
  overridability(지금도 weak인지)를 재확인하지 않았다.**
- 지문은 args만 고정할 뿐 계보 상태를 인코딩하지 않는데, evidence(연결의
  weak/strong)는 `previewParentLinks`가 판정 때마다 현재 스토어 기준으로
  재계산한다. → 승인~소비 사이에 `recordToolResult`로 새 노드가 생겨 같은 값이
  strong으로 재분류되면(긴 토큰 VALUE_MATCH/MCP_REF), "확정 차단이어야 할
  strong 트라이펙타"가 낡은 승인으로 통과한다.

### 모델 (전이 ↔ 코드)

| TLA+ 전이 | 실제 코드 | 비고 |
|---|---|---|
| `CreateNode(n, own, st)` | `recordToolResult` + `resolveParents`의 연결 분류 | 태그·신뢰도 비결정 = 과근사 |
| `Offer(n)` | `evaluateOverridability`=true → `offerOverride` | guard `strength="weak"` = "오염 실은 노드 전부 weak" |
| `Approve/Reject(n)` | `requestApproval` + `resolveApproval` | PENDING은 OFFERED에 접음(부기 전이) |
| ★ `Escalate(n)` | 승인 후 `recordToolResult` → 같은 args가 strong 재분류 | hitl 상태 무관하게 발생 가능 — TOCTOU의 심장 |
| ★ `ConsumeSink(n)` | `consumeApprovalIfMatching` + index.ts 소비 분기 | 1단계: **weak 재확인 의도적 부재(당시 코드)** → 2단계: `strength[n] = snap[n]` guard 추가(지문 대조) |
| ★ `ConsumeStale(n)` (2단계 신규) | 소비 시 지문 불일치 → `used=true` 영구 무효 + null(차단 유지) | exfiltrated 불변 — 아무것도 안 나감. 이후 재평가에서 새 제안 자동 발급과 대응 |
| `Offer(n)`의 `snap` 기록 (2단계) | `offer.lineageFingerprint` 저장 | 제안 시점 계보 지문의 모델판 |
| `ReachSinkClean(n)` | 트라이펙타 아님 → 통과 | |

단순화: 호출↔노드 1:1(지문 고정 ↔ 노드 식별자 고정), evidence 단일 노드
(`evaluateOverridability`의 단일 노드 환원), parents/정화 제외(기존 모델이 증명한
직교 축). 상세는 TaintHITL.tla 머리 주석.

### 1단계 결과: HITLSafety 위반 — 예측한 TOCTOU 경로 그대로 (5스텝 최단 반례)

> **HITLSafety**: strong 연결로 오염을 실은 트라이펙타는 어떤 승인으로도 sink에
> 도달할 수 없다 (`Trifecta(tagsAtExit) ⇒ strengthAtExit="weak"`).

TLC 실행 결과 (노드 3개, TLC 2026.07): **위반. 최단 반례 5스텝** —

```text
1. CreateNode(n1, {SENSITIVE,UNTRUSTED}, "weak")   weak 트라이펙타 차단 발생
2. Offer(n1)          evaluateOverridability=true → offerOverride (승인 가능 제안)
3. Approve(n1)        사람이 승인 (이 시점엔 weak — 승인이 정당했다)
4. Escalate(n1)       recordToolResult로 같은 값이 strong 재분류 (승인은 그대로 유효)
5. ConsumeSink(n1)    consumeApprovalIfMatching: 지문 일치+APPROVED+미사용 → 통과
   ⇒ exfiltrated에 [tags={S,U}, strengthAtExit="strong"] — HITLSafety 위반
```

반례가 "우연히" TOCTOU인 게 아니라 **구조적으로 다른 경로가 불가능**하다:
strong 트라이펙타 유출은 ConsumeSink뿐(Clean은 ¬Trifecta guard) → APPROVED 필요
→ Offer 필요 → Offer는 weak guard → strength 변경은 Escalate뿐. 즉 어떤 반례든
반드시 Offer→Approve→Escalate→Consume 순서를 포함한다.

- 모델 건전성(반례가 모델 오류가 아님): HITLSafety를 뺀 실행에서 나머지 불변식
  (TypeOK / TrifectaExitOnlyViaOverride / Unborn)은 **18,974,173 상태 생성 /
  4,173,281 고유 상태 전수 탐색(깊이 37), 위반 0** (34초). 특히
  TrifectaExitOnlyViaOverride = "트라이펙타의 유일한 탈출구는 HITL" — 기본 차단
  guard는 온전하고, 구멍은 정확히 오버라이드 소비 경로 하나다.
- 1단계 시점의 버그 재현 모델(ConsumeSink에 재확인 guard 없는 버전)은 git
  이력에 있다 — 현재 TaintHITL.tla는 아래 2단계 수정을 반영한 버전.

### 2단계 수정: 방법 B — 승인 시점 계보 지문 저장·대조 (hitl.ts)

두 후보 중 **더 견고한 B를 채택** (견고함 > 복잡도):

- **A(소비 시 overridability 재계산)**: strong 승격은 막지만, evidence가 승인
  시점과 완전히 달라져도 "여전히 weak 클래스"면 통과 — **승인 이식**(사람이 본
  것과 다른 위험 그림을 낡은 승인이 커버)을 못 막는다.
- **B(계보 지문 대조)**: 제안 시점 evidence의 canonical hash(노드 id·weak·
  tags 정렬 + argTags + linkMethod, sha256 32hex)를 `offer.lineageFingerprint`
  로 저장, 소비 시점에 현재 evidence로 재계산해 **일치할 때만** 통과. B ⇒ A
  (제안 guard가 weak이므로 "일치" ⇒ "여전히 weak"). 지문의 완전성 = 방어의
  완전성이므로 판정 입력 전부를 넣었다.

수정 동작 (전부 결정론, AI 호출 0, fail-safe는 기존 try/catch가 흡수):

- 소비 시 지문 불일치 → 승인 **영구 무효**(used=true, audit `OVERRIDE_STALE`)
  + 차단 유지. 한 번이라도 다른 상태를 거친 승인은 상태가 되돌아와도 재사용 불가.
- 제안 재사용(approvalId 안정성)도 지문 일치일 때만 — 제안 후 계보가 달라지면
  낡은 제안을 `SUPERSEDED`로 봉인하고 새 제안 발급 (낡은 그림의 승인 자체를 차단).
- 여전히 weak면 재평가에서 새 제안이 자동 발급 — 정상 HITL 흐름은 유지된다.
- ★팀 공지(시그니처 변경): `offerOverride(ctx, evidence)` /
  `consumeApprovalIfMatching(ctx, evidence)` — evidence 인자 추가. 호출처는
  index.ts `computeLineageDecision` 각 1곳뿐.

### 2단계 결과: 위반 0 (안전 증명) + 비공허성 witness (HITL 여전히 동작)

모델에 같은 재검증을 반영(ConsumeSink guard `strength[n] = snap[n]` +
ConsumeStale 전이)한 뒤:

1. **본 실행 (위반 0)**: 불변식 5종(TypeOK / ★HITLSafety /
   TrifectaExitOnlyViaOverride / Unborn / SnapConsistency) —
   **17,586,301 상태 생성 / 3,723,875 고유 상태 전수 탐색(깊이 34), 위반 0**
   (35초, TLC 2026.07, 노드 3개). 1단계 반례의 마지막 스텝(Consume)이 지문
   대조 guard로 비활성화됨을 전수 탐색이 확인.
2. **비공허성 witness ("다 막아서 0"이 아님)**: `NoOverrideExit`(오버라이드
   유출이 하나도 없다) 불변식을 넣은 witness 변형(스크래치패드, 원본 무수정)에서
   TLC가 4스텝 "반례" = **정상 승인 통과 witness**를 즉시 내놓는다:
   `CreateNode(weak {S,U}) → Offer → Approve → ConsumeSink` —
   `strengthAtExit="weak"`, `via="OVERRIDE"`. 계보가 안 변한 weak 승인은
   여전히 통과한다 = HITL은 무용지물이 아니다. TrifectaExitOnlyViaOverride는
   본 실행에서 전 상태 성립(트라이펙타의 유일한 출구는 여전히 HITL뿐).
3. **구현 테스트**: 기존 123개 무수정 통과 + 신규 4개
   (`src/hitl.toctou.test.ts`) = **127 pass / 0 fail**:
   - ★T1 TOCTOU 회귀: 승인 후 strong 재분류(≥16자 토큰 VALUE_MATCH) → 낡은
     승인 미소비 + `canOverride:false` 확정 차단 + audit `OVERRIDE_STALE` —
     1단계 반례 시나리오의 코드판이 막힘.
   - T2 영구 무효: 무효화된 승인은 이후 어떤 재평가에서도 소비 불가.
   - T3 B의 엄격함: 변경됐지만 여전히 weak(승인 이식 시도) → 낡은 승인 무효,
     단 새 제안 발급 → 재승인하면 통과 (A였다면 낡은 승인이 그대로 통과했을 케이스).
   - T4 정상 케이스: 계보 무변화 → 승인 그대로 1회 통과.

## 가지치기(묘비 압축) — PruneSafety 증명 + 교환성 발견→수정 (TaintPruning / TaintPruningCommute)

`pruneSessionLineage`(lineage.ts)의 핵심 안전성 "가지치기 전후 판정 불변"을 두 층으로
전수 증명했다. fast-check(★판정 보존, pruning.test.ts)의 설계판이자, 그 테스트가
못 보던 구멍의 발견→수정 기록이다.

### 1층 — 상태-점별 보존 (TaintPruning.tla): 위반 0

> **PruneSafety**: 모든 도달 가능 상태 × 모든 프로브(무참조 폴백 / `_taintRef` 명시
> 참조 / 값 매칭)에서, "묘비 압축된 실세계"와 "아무것도 안 지운 이상세계"의 sink
> 판정이 같다. Prune 전이는 pruned만 바꾸고 이상세계 판정은 pruned와 무관하므로
> "Prune 직전 판정 = 직후 판정"(테스트의 ★속성)이 따름정리로 나온다.

- 검증 결과: 노드 4개 기준 **2,775,761 상태 생성 / 352,346 고유 상태 전수 탐색
  (깊이 12), 위반 0** (35초, TLC 2026.07). 불변식 5종(TypeOK / ★PruneSafety /
  PrunedClean / ParentsExist / Unborn) 전부 cfg 활성.
- 모델링 결정: 판정을 ReachSink 전이 + exfiltrated 스냅샷 대신 **상태 함수**
  `Blocked(kind, R)`로 — "가지치기 전 스냅샷 보관"이 필요 없어 상태가 작고,
  모든 상태에서 모든 프로브를 동시 검사하므로 더 강하다. 묘비의 id+resultTokens
  보존은 "pruned 노드에 대한 참조가 여전히 해소된다"(R ⊆ created)로 표현.
- 비공허성 witness 3종(스크래치패드 변형, 반례 트레이스로 확보): 가지치기 발생 후에도
  frontier 차단 유지 / 무참조는 차단인데 묘비 참조는 통과 / 자식 먼저→부모 승격 연쇄.
- mutation sanity 2종 — 불변식이 살아있음을 양방향으로: clean guard 제거 →
  묘비가 오염을 숨겨 **유출 방향** 3스텝 반례. 묘비 없는 완전 삭제 → 깨끗 참조가
  폴백 강등돼 **과차단 방향** 4스텝 반례 ("노드를 통째로 지우면 통과→차단"이라는
  묘비 주석의 형식적 확인).

### 2층 — 교환성 구멍: 발견 (1단계, 반례) → 수정 → 재증명 (TaintPruningCommute)

1층은 "묘비가 그래프에 **있던** 정보를 잃지 않음"이다. 더 강한 질문 — "prune과
**미래** 연산이 교환하는가"(가지치기 낀 세션 ≡ 없던 세션) — 에는 수정 전 코드가
반례를 갖고 있었다. fast-check는 prune을 항상 시퀀스 마지막에 두므로 관측 불가.

**1단계 (버그 재현판 — git 이력)**: 두-세계 lockstep(태그 두 벌: 절단 vs 관통)에서
**CommuteSafety 위반, 최단 반례 5스텝** 양방향:

```text
유출:   Create(n1 깨끗 루트) → Create(n2, 부모 n1) → Create(n3 {U})
        → Prune(n2) → AddTag(n1, S)   ⇒ REF{n2}: 이상세계 차단 / 실세계 통과
        수정 전 prune이 childIndex 엣지를 지워 cascade가 묘비에서 절단 —
        묘비는 resultTokens로 참조가 여전히 해소되므로 그 값이 조용히 나간다.
과차단: 같은 골격에서 MATCH{n2} — "묘비=무조건 깨끗" 취급이라 재오염 묘비를
        잡은 값 매칭에서 안전 바닥(fail-open 3차 수정)이 오발동해 차단.
```

- 코드 재현 확인: 쌍둥이 세션(가지치기 유/무) 프로브 — 수정 전 `allowed: true` vs
  `false`로 실측 발산 (현 `pruning.commute.test.ts` T1이 그 시나리오의 회귀 테스트).
- 모델 건전성: CommuteSafety 제외 불변식(TypeOK/WorldMono/ParentsExist/Unborn)은
  35,290 상태 위반 0. WorldMono(실세계 태그 ⊆ 이상세계)가 "절단은 덜 퍼뜨리는
  방향으로만 발산 = 유출 방향"임을 구조적으로 보였다.

**2단계 (수정 — "재오염 가능 묘비", model-first)**: 코드보다 모델을 먼저 고쳐
TLC로 의미론을 확정한 뒤 이식했다. 더 약한 안(cascade 관통만, 묘비 tags 없이)은
묘비 자기 참조 프로브가 여전히 발산함을 손 시뮬레이션으로 확인하고 기각.

- 묘비 = `{resultTokens, tags, parents}` — tags는 prune 시점 항상 `{}`(clean guard),
  이후 **cascadeDown 관통으로만 증가** (grow-only, 정화 불가 — fail-closed).
- prune이 childIndex 엣지 유지, childless 판정은 "live 자식 없음" (연쇄 fixpoint 유지).
- 판정 5곳이 묘비 태그 반영: ① evidence unionTags(shadow.ts) ② 안전 바닥
  resolvedTaint ③ 생성 상속 ④ sessionHasLiveTag ⑤ frontier(후보+커버).
  안전 바닥과의 관계는 충돌이 아니라 정확화 — 바닥의 의도("오염 출처 미식별 =
  의심 = 차단")에서 재오염 묘비를 잡은 매칭은 "출처 식별"이므로 바닥을 건너뛴다.
  묘비 tags는 평소 비어 있어 기존 fail-open 3차 수정 동작은 그대로다.
- 묘비 직접 `addNodeTags`는 여전히 throw(fail-closed) — 조용한 경로(cascade)만 관통.

**2단계 결과**:

1. **모델 (위반 0)**: 두-저장소 메커니즘(tagsL=live, tagsT=묘비 vs 이상세계 단일
   저장소)을 정직하게 모델링 — **33,514 상태 생성 / 6,906 고유 전수 탐색(깊이 13),
   불변식 7종(★CommuteSafety / CommuteNoLeak / CommuteNoOverblock /
   ★StoreFaithful(태그 수준 동치) / TypeOK / ParentsExist / Unborn) 위반 0**.
   비공허성 witness: 묘비가 cascade로 실제 태그를 받는 상태 도달(4스텝 트레이스).
2. **구현 테스트**: 기존 127개 무수정 통과 + 신규 4개(`src/pruning.commute.test.ts`)
   = **131 pass / 0 fail**: ★T1 유출 회귀(반례 시나리오 → 차단) / T2 묘비 너머
   live 자손까지 관통 전파 / T3 과차단 해소(재오염 묘비 잡은 매칭 = 바닥 미발동) /
   ★T4 fast-check 강화판 — prune을 시퀀스 **중간**에 끼우고 쌍둥이 세션과 전 프로브
   판정 비교 (기존 fast-check가 못 보던 계열의 상시 감시).
3. **과차단·성능 회귀 없음**: 벤치마크 오탐률 수정 전후 동일 — lineage 정상 오탐
   5/50 = **10.0%** (boundary 5/10, easy 0/40), 미탐 4.3%, 승패 케이스 목록 불변.

### 1층 모델의 의미론 시점

TaintPruning.tla는 **수정 전(절단) 의미론의 보존 기록**이다 — 수정 전 코드에서도
상태-점별 보존은 성립했다(fast-check ★판정 보존이 통과하던 이유가 바로 이것).
현재 lineage.ts와의 전이 대응은 TaintPruningCommute.tla(수정판)를 기준으로 볼 것.

## 파괴적 액션 게이트 — model-first 신규 설계 (TaintDestructiveHITL)

기존 모델들이 "발견→수정"이었다면 이건 **설계 선행**이다: 구현 전에 모델을 먼저
작성·검증해 의미론을 확정하고 코드로 이식했다(가지치기 2단계와 같은 관례).
게이트의 요구사항은 "삭제 자체가 아니라 **비신뢰 출처가 유발한 파괴**만 차단" —
판정 술어는 `destructiveTools 등록 도구 AND 세션 U-집합 비어있지 않음`이고,
HITL(destructivePolicy:"hitl")은 승인 시점 U-집합 스냅샷을 지문으로 저장해
소비 시점과 대조한다(TaintHITL 2단계 메커니즘의 동형 재사용 — 단 상태 공간이
값-계보 strength가 아니라 **U-집합의 증가/감소**).

기존 TaintHITL이 커버 못 하는 새 축 3가지가 이 모델의 존재 이유: ① 판정 술어가
다르고(트라이펙타 vs 세션 U-존재) ② 변이 알파벳이 다르고(strength 승격 vs
ReadUntrusted/DeclassifyU) ③ 기계가 둘이다(유출·파괴 게이트의 offers 저장소
교차 간섭은 단일 기계 모델로 표현 불가).

### 검증된 불변식 (본 실행: SharedKeys=FALSE, 위반 0) — ★F1 수정 반영판

★ **F1 수정 (정화 세탁 미탐 P6)**: 이전 모델은 `DExecNoU`(승인 없는 삭제)를
`uSet = {}`(살아있는 U 없음)에 활성화했다. 그런데 `DeclassifyU`(정화)가 uSet을 비울
수 있어, 공격자가 비신뢰 콘텐츠를 정화해 uSet을 비운 뒤 승인 없이 삭제가 실행됐다.
즉 이전 `DestructiveSafety("NO_U는 uAtExit={}이면 안전")`가 F1을 안전으로 **잘못
모델링**하고 있었다. 수정: 세션 노출이력 `exposure`(grow-only, DeclassifyU가 못 끔)를
두고, `DExecNoU`는 `~exposure`일 때만, `DOffer`(HITL)는 `exposure`일 때 활성화한다.

> **DestructiveSafety** (F1 강화): 노출된 세션(exposureAtExit)의 파괴 실행은 전부
> 사람 승인(OVERRIDE) 경유. 역방향 — 승인 없는(NO_U) 실행은 반드시 **노출이력 없는**
> 세션 = 사용자 직접 지시 삭제만 승인 없이 통과(과차단 아님). ★이전판은 "uAtExit={}"
> 라 정화로 uSet을 비운 NO_U 실행을 안전으로 오판했다(P6) — 이제 exposureAtExit로 판정.
>
> **ExposureMonotone**: `exposure`는 한 번 TRUE가 되면 어떤 전이(DeclassifyU 포함)도
> FALSE로 못 돌린다 — 정화가 파괴 축을 세탁하지 못함의 형식적 근거.
>
> **ApprovalFreshness** (TOCTOU): 승인 경유 실행은 실행 시점 U-집합 = 제안 시점
> 스냅샷일 때만. id 신선성(정화된 노드 id 재사용 불가 = 코드 tn_uuid) 덕에 "달라졌다
> 되돌아온 집합"은 존재 불가.
>
> **GateIsolation**: 파괴 게이트의 어떤 행동도 유출 offer를 봉인(SUPERSEDED)·
> 소각(STALE)하지 못하고 역방향도 동일 — 코드 수정(hitl.ts 지문에 gate 판별자
> 포함 = offer 공간 서로소)의 모델판. **TaintHITL의 전제("유출 offers는 유출
> 게이트만 만진다")가 파괴 게이트 추가 후에도 유지되는 근거.**

- 검증 결과 (수정판): UNodes 2 × Calls 2 기준 **20,641,001 상태 생성 / 3,695,500
  고유 상태 전수 탐색(깊이 41), 불변식 5종(TypeOK / ★DestructiveSafety /
  ★ApprovalFreshness / ★GateIsolation / SnapConsistency) + 속성 ExposureMonotone
  위반 0** (28초, TLC 2026.07).
- ★ **F1 버그 재현**: `DExecNoU` guard를 옛 `uSet = {}`로 되돌린 변형에서
  **DestructiveSafety가 4스텝 반례로 깨짐**: `ReadUntrusted(u1) → DeclassifyU(u1) →
  DExecNoU(c1)` — 정화로 uSet을 비운 뒤 승인 없는 삭제(exposureAtExit=TRUE, via=NO_U).
  수정판(`~exposure`)에서 그 스텝이 비활성 = 차단. (P6의 형식판.)
- **버그 재현 (설계 검토에서 발견한 구멍의 실재 증명)**: 수정 전 설계(지문에 gate
  없음 = naive 공유 키)는 별도 git 이력이 아니라 **모델 내 `SharedKeys` 상수**로
  보존했다. `SharedKeys=TRUE` 변형(스크래치 cfg)에서 GateIsolation이 **4스텝
  반례로 즉시 깨진다**: `ReadUntrusted(u1) → DOffer(c1) → CrossSupersedeByE(c1)`
  — 유출 게이트의 제안이 진행 중인 파괴 제안을 지문 충돌로 봉인(사람이 승인
  중이던 approvalId가 소리 없이 죽는 시나리오).
- 비공허성 witness 2종 (스크래치 cfg, 원본 무수정): `NoOverrideExit` 반례 5스텝 =
  정상 승인 흐름 통과(`Read → DOffer → DApprove → DConsume`, U-그림 무변화);
  `NoNoUExit` 반례 2스텝 = 직접 삭제가 승인 없이 통과(`DExecNoU`) — "무조건 막는
  게이트가 아님"의 형식적 확인.
- mutation sanity: DConsume의 지문 대조 guard(`uSet = dSnap[c]`) 제거 변형에서
  ApprovalFreshness가 **5스텝 반례**로 깨진다: 승인 후 `DeclassifyU`로 U-그림이
  변했는데도 실행 — guard가 공허하지 않게 실제로 일하고 있다.
- 구현 대응: config.ts(`destructivePolicy`/`destructiveTools`), index.ts
  `computeDestructiveDecision`·`evaluateToolCall` 합성(승인 소각 방지 peek
  프로토콜), hitl.ts gate 판별자 + `peekApprovalMatches`, lineage.ts
  `collectLiveTagHolders`(U-스냅샷 = 승인 지문 입력). ★F1 수정 후 파괴 게이트
  발동은 노출이력(`sessionExposure`, index.ts)이라 정화로 못 품 — HITL 승인만 해제.
- **F1 근본 수정(노출이력) 총괄**: 유출·파괴 양축의 U 판정을 세션 노출이력
  (`sessionExposure`, grow-only)으로 통일. U 태깅(`addSessionTags`)에서 세팅,
  정화는 못 끔. 유출은 `valueSensitive AND exposure`(RE35/RE36 과차단 없음),
  파괴는 `exposure`(HITL만 해제). 회귀 테스트: `f1-exposure.test.ts`(C1 차단 +
  RE35/RE36 유지 + 단조성), `destructive*.test.ts` P6 앵커, property.test.ts
  RefModel 오라클도 노출이력으로 정정. 전체 **199 pass / 0 fail**. 벤치마크
  lineage 오탐/미탐 F1 전과 동일(RB01-05 흐름분리·RS09 회귀 불변).

## 구현 검증 (fast-check)

TLA+가 "설계"의 SinkSafety를 증명했다면, `src/property.test.ts`는 같은 속성을
**실제 구현**(lineage.ts + index.ts의 `judgmentMode: "lineage"`)에 대해 수만 개
랜덤 호출 시퀀스로 재현 검증한다. 둘은 짝이다:

> 검증 사슬: **TLA+** (설계 증명, 364만 상태 전수) → **RefModel** (TLA+ 모델의
> 코드판 — 순환성 없는 독립 오라클) → **fast-check** (구현, 수만 랜덤 시나리오)
> → **단위 테스트 90개** (개별 로직)

| 속성 | 내용 | 실행 횟수 |
|---|---|---|
| P1 ★SinkSafety | 랜덤 시퀀스에서 트라이펙타 계보 ⇔ 차단 (**양방향** — 유출도 과차단도 반례) | 5,000 |
| P2 단방향 | 자식 생성이 부모 노드 태그를 절대 못 바꿈 | 3,000 |
| P3 비대칭 | 부모 정화가 자식 태그를 자동으로 떼지 않음 | 3,000 |
| P4 fail-safe | real 계산 실패 시 절대 통과 없음 (차단) | 2,000 |
| 비공허성 | 아래 카운터 6종 전부 > 0 강제 | — |

- **공허하지 않음 보장** (TLA+ sanity check와 같은 정신): 생성기가 위험 케이스를
  실제로 만들었는지 6종 카운터(트라이펙타 생성 / 차단 / 통과 / 정화 성공·실패 /
  fail-safe)를 집계하고 **전부 > 0을 assert** — 안전한 시퀀스만 생성되면 테스트
  자체가 실패한다. 실측: 트라이펙타 11,732 생성, 차단 11,867, 통과 8,706.
- 반례 발생 시 fast-check가 자동 shrinking으로 최소 재현 시퀀스 + seed를 출력한다.
- 실행: `npm test --workspace=@icarus-tether/policy-engine` (전체 스위트에 포함),
  실행 횟수는 `FC_NUM_RUNS` 환경변수로 조절.

## 모델 ↔ 실제 코드 대응표

| TLA+ | 실제 코드 | 대응 내용 |
|---|---|---|
| `created`, `tags`, `parents` | `lineage.ts`의 `lineageStore`, `TaintNode.tags`, `TaintNode.parents` | 세션 계보 그래프 상태 |
| `CreateNode(n, own, ps)` | `createTaintNode()` | 노드 생성 + 전파. `tags' = own ∪ ⋃ parents.tags` = `effectiveTags` 계산. `ps ⊆ created` = 부모는 항상 먼저 생성된 노드(DAG, 역류·사이클 원천 불가) |
| `own`/`ps` 비결정 선택 | `resolveParents()`의 3층 연결 (MCP_REF / VALUE_MATCH / TEMPORAL_FALLBACK) + `classifySourceTags`/`detectSecrets` | **과근사**: 실제 로직이 어떤 부모·태그를 만들든 모델의 한 경우. 모델이 안전하면 어떤 연결 결과도 안전 |
| `Declassify(n, t)` | `declassifyNodeTag()` | 그 노드 하나만 태그 제거. **액션에 자식 항이 없음 = 코드에 자손 순회가 없음** (비대칭). `parents` UNCHANGED = 소급 수정 금지 |
| `Declassify`가 아무 때나 가능 | `attemptSanitization()` 검증 통과 시에만 호출 | 과근사: 정화가 언제 어떤 순서로 일어나도 안전 |
| `ReachSink(n)` guard | `computeLineageDecision()` (`judgmentMode: "lineage"`) | 차단 규칙: 트라이펙타 값은 전이 비활성 = `allowed: false`. OUTBOUND_SINK 분류는 이 전이의 존재 자체가 표현 |
| `exfiltrated`의 `tagsAtExit` | (판정 시점의 계보 상태) | 통과 시점 태그 스냅샷 — 사후 정화가 판정 기록을 소급 왜곡하지 못하게 |
| `SinkSafety` 불변식 | 시스템 전체의 안전 목표 | 트라이펙타 유출 불가능 |
| `ParentsExist` 불변식 | 계보 3대 불변식 중 "소급 금지 + DAG" | 부모는 항상 자기보다 먼저 생성된 다른 노드 |

## 모델링하지 않은 것 (의도적 범위 제한)

- **session/shadow 판정 모드** (`judgmentMode: "session" | "shadow"`): toy 판정은
  `TaintSafety.tla`가 다루고, 이 모델은 real(lineage) 판정만 다룬다.
- ~~live 전파~~ → **TaintLineageLive.tla로 증명 완료** (위 섹션). snapshot 모델
  (TaintLineage.tla)은 여전히 "생성 후 태그 불증가" 가정 + 1회 통과 단순화를
  유지하지만, live 모델이 그 가정을 해제한 상태에서도 SinkSafety가 성립함을
  보였으므로 경고가 해소됐다.
- **정화의 검증 로직** (스키마 추출·토큰화·재스캔): 모델은 "정화가 일어난다"만 보고
  "올바른 값만 정화된다"는 sanitization.ts의 단위 테스트가 보증한다. 역할 분담:
  TLA+는 순서·동시성의 전수 탐색, 테스트는 개별 변환의 정확성.
- **argTags**: 인자에 실려오는 태그는 모델에서 해당 값 노드의 `own` 태그로 흡수된다.
- **세션 격리**: 모델은 단일 세션. 세션 간 상태 공유가 없으므로(코드에서 Map 키로
  격리) 다중 세션은 단일 세션의 독립 병렬 — 안전성에 새 경우를 더하지 않는다.

## 실행 방법

```bash
cd policy-engine/formal
java -cp <tla2tools.jar 경로> tlc2.TLC -deadlock -workers auto TaintLineage.tla
java -cp <tla2tools.jar 경로> tlc2.TLC -deadlock -workers auto TaintLineageLive.tla
java -cp <tla2tools.jar 경로> tlc2.TLC -deadlock -workers auto TaintHITL.tla
java -cp <tla2tools.jar 경로> tlc2.TLC -deadlock -workers auto TaintPruning.tla
java -cp <tla2tools.jar 경로> tlc2.TLC -deadlock -workers auto TaintPruningCommute.tla
java -cp <tla2tools.jar 경로> tlc2.TLC -deadlock -workers auto TaintDestructiveHITL.tla
```

- TaintHITL은 **위반 0이 정상** (2단계 수정 반영판 — 위 섹션). 1단계 버그
  재현판(반례 5스텝)은 git 이력 참조. TaintPruning·TaintPruningCommute도
  **위반 0이 정상** — Commute의 1단계 재현판(반례 5스텝) 역시 git 이력 참조. 반례/witness의 최단 트레이스를 보려면
  `-workers 1`로 (병렬 BFS는 같은 깊이의 다른 반례를 먼저 보고할 수 있다).
  TLC가 남기는 `*_TTrace_*.tla/.bin`과 `states/`의 새 타임스탬프 디렉토리는
  생성물이니 커밋하지 말 것.

- `tla2tools.jar`는 VS Code TLA+ 확장에 번들됨:
  `~/.vscode/extensions/tlaplus.vscode-ide-*/tools/tla2tools.jar`
- `-deadlock` 필수: 유한 모델이라 모든 노드가 생성·정화·통과되면 자연 종료한다
  (교착이 정상 종료 상태).
- 탐색이 느리면 `TaintLineage.cfg`의 `Nodes`를 `{n1, n2, n3}`으로 줄일 것.
