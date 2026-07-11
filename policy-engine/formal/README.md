# policy-engine 형식검증 (TLA+ / TLC)

값 단위 taint 계보의 핵심 안전 속성을 TLC 모델 체커로 전수 탐색해 증명한다.

| 모듈 | 무엇의 모델인가 |
|---|---|
| `TaintSafety.tla` | 세션 단위 boolean 판정(toy) — 1주차 최소 모델 |
| `TaintLineage.tla` | **값 단위 계보 판정(real)** — 전파 + 비대칭 정화 + 차단 규칙 |

## 증명된 속성 (TaintLineage)

> **SinkSafety**: 어떤 실행 순서로도, SENSITIVE와 UNTRUSTED를 둘 다 가진 노드가
> (정화되지 않은 채) sink에 도달하는 것은 불가능하다.

- 검증 결과: 노드 4개 기준 **16,852,481 상태 생성 / 3,637,018 고유 상태 전수 탐색,
  위반 0** (TLC 2026.05, 76초).
- sanity check: `ReachSink`의 차단 guard(`~Trifecta(tags[n])`)를 제거한 변형에서는
  SinkSafety가 4스텝 반례로 **즉시 깨짐**을 확인 — 불변식이 공허하게 참이 아니라
  실제로 차단 규칙 덕에 성립함을 보인다.

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
- 실행: `npm test --workspace=@taintguard/policy-engine` (전체 스위트에 포함),
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
- **live 전파** (`addNodeTags` + `cascadeDown`): 생성 후 태그가 "늘어나는" 유일한
  경로. 이 모델은 snapshot 의미론(생성 시 1회 상속)만 다룬다. live를 추가하면
  `AddTag` 전이(자손 하향 전파)가 필요하다 — 다음 확장 후보.
  주의: 그 경우 "노드당 1회 sink 통과" 단순화의 정당화(태그가 절대 안 늘어남)를
  재검토해야 한다 (통과 후 태그가 늘 수 있으므로 재통과를 허용해야 함).
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
```

- `tla2tools.jar`는 VS Code TLA+ 확장에 번들됨:
  `~/.vscode/extensions/tlaplus.vscode-ide-*/tools/tla2tools.jar`
- `-deadlock` 필수: 유한 모델이라 모든 노드가 생성·정화·통과되면 자연 종료한다
  (교착이 정상 종료 상태).
- 탐색이 느리면 `TaintLineage.cfg`의 `Nodes`를 `{n1, n2, n3}`으로 줄일 것.
