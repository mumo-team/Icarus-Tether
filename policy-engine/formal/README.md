# policy-engine 형식검증 (TLA+ / TLC)

값 단위 taint 계보의 핵심 안전 속성을 TLC 모델 체커로 전수 탐색해 증명한다.

| 모듈 | 무엇의 모델인가 |
|---|---|
| `TaintSafety.tla` | 세션 단위 boolean 판정(toy) — 1주차 최소 모델 |
| `TaintLineage.tla` | **값 단위 계보 판정(real)** — snapshot 전파 + 비대칭 정화 + 차단 규칙 |
| `TaintLineageLive.tla` | **live 전파 확장** — addNodeTags+cascadeDown(사후 오염·하향 전파) + sink 재통과 |
| `TaintHITL.tla` | **HITL 오버라이드 — TOCTOU 재현** ★ 통과가 아니라 "반례가 나와야 정상"인 버그 재현 모델 |

## 증명된 속성 (TaintLineage)

> **SinkSafety**: 어떤 실행 순서로도, SENSITIVE와 UNTRUSTED를 둘 다 가진 노드가
> (정화되지 않은 채) sink에 도달하는 것은 불가능하다.

- 검증 결과 (snapshot, TaintLineage): 노드 4개 기준 **16,852,481 상태 생성 /
  3,637,018 고유 상태 전수 탐색, 위반 0** (TLC 2026.05, 76초).
- sanity check: `ReachSink`의 차단 guard(`~Trifecta(tags[n])`)를 제거한 변형에서는
  SinkSafety가 4스텝 반례로 **즉시 깨짐**을 확인 — 불변식이 공허하게 참이 아니라
  실제로 차단 규칙 덕에 성립함을 보인다.

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

## HITL 오버라이드 TOCTOU — 형식검증이 실제 버그를 발견 (TaintHITL)

앞의 두 모델과 목적이 반대다: 안전 속성의 성립을 증명하는 게 아니라, **지금 코드의
승인 재검증 누락(TOCTOU)을 그대로 모델링해 TLC가 위반 반례를 내놓는지** 확인한다.
반례가 나오는 것 자체가 "버그가 설계 수준에서 실재한다"는 증거다.

### 문제 (코드 근거)

- `consumeApprovalIfMatching`(hitl.ts)은 지문 `sha256(sessionId|toolName|args)`
  일치 + APPROVED + 미사용, 이 셋만 보고 승인을 소비한다. **소비 직전에
  `evaluateOverridability`(지금도 weak인지)를 재호출하지 않는다** (index.ts의
  소비 분기에는 재확인이 없고, overridability는 차단 후 "제안 여부"에만 쓰인다).
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
| ★ `ConsumeSink(n)` | `consumeApprovalIfMatching` + index.ts 소비 분기 | **guard에 weak 재확인이 의도적으로 없음 = 지금 코드** |
| `ReachSinkClean(n)` | 트라이펙타 아님 → 통과 | |

단순화: 호출↔노드 1:1(지문 고정 ↔ 노드 식별자 고정), evidence 단일 노드
(`evaluateOverridability`의 단일 노드 환원), parents/정화 제외(기존 모델이 증명한
직교 축). 상세는 TaintHITL.tla 머리 주석.

### 결과: HITLSafety 위반 — 예측한 TOCTOU 경로 그대로 (5스텝 최단 반례)

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
- **다음 단계 (미착수)**: 소비 시점에 overridability 재검증을 추가
  (`consumeApprovalIfMatching` 또는 index.ts 소비 분기에서 재확인) 후, 같은
  모델에 재확인 guard를 넣은 변형으로 위반 0을 재검증. 현재 hitl.ts/index.ts는
  무수정 — 이 단계는 "문제 재현"까지다.

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
```

- TaintHITL은 **HITLSafety 위반 + 반례 트레이스가 출력되어야 정상** (버그 재현
  모델 — 위 섹션). 최단 반례를 보려면 `-workers 1`로 (병렬 BFS는 같은 깊이의
  다른 반례를 먼저 보고할 수 있다). TLC가 남기는 `*_TTrace_*.tla/.bin`과
  `states/`의 새 타임스탬프 디렉토리는 생성물이니 커밋하지 말 것.

- `tla2tools.jar`는 VS Code TLA+ 확장에 번들됨:
  `~/.vscode/extensions/tlaplus.vscode-ide-*/tools/tla2tools.jar`
- `-deadlock` 필수: 유한 모델이라 모든 노드가 생성·정화·통과되면 자연 종료한다
  (교착이 정상 종료 상태).
- 탐색이 느리면 `TaintLineage.cfg`의 `Nodes`를 `{n1, n2, n3}`으로 줄일 것.
