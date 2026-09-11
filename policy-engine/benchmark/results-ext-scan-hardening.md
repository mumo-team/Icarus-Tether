# 출력 스캔 강화 — 단계별 측정 기록

- 세트: `benchmark/scenarios-ext.ts` (커밋 bb0a2e9 동결, 무수정)
- 실행 A 설정: `benchmark/config.dev-bench.json` · 실행 B 설정: `benchmark/config.dev-bench-ext.json` (둘 다 무수정)
- 각 단계 후 `npm test`, 기존 81(realistic)·boundary 11 레코드 단위 대조, 확장 A/B 재실행.
- "스캔 독립 탐지"는 실행 B(lineage)의 공격 판정 지점 105개 중 출력 스캔이 자체 근거를 낸 수. 판정 객체의 `outputScan` 필드로 셌다.
- "fallback-only 미탐지"는 계보 연결이 TEMPORAL_FALLBACK뿐이고 스캔도 못 잡은 공격 지점 수. 바닥 완화 규칙을 넣으면 그대로 미탐이 되는 수다(규칙은 아직 미적용).
- 바닥 완화 규칙은 이 기록 시점에 적용하지 않았다. 아래 "완화 시 미탐률"은 기존 판정 기록으로 계산한 시뮬레이션이다.

## 단계별 수치

| 단계 | 변경 | npm test | 기존 81 · boundary 11 | 확장 A 오탐/미탐 | 확장 B 오탐/미탐 | B 스캔 독립 탐지 | B fallback-only 미탐지 | 완화 시 미탐률 (시뮬레이션) |
|---|---|---|---|---|---|---|---|---|
| 0 (기준) | 없음 | 277 / 277 | 기준선 | 35 / 66 | 73 / 0 | 72 / 105 | 33 | 31.4% |
| 1 | 출처 기반 needle 문턱 6 (`SensitivePayload.origin`) | 282 / 282 | 변화 0건 | 35 / 66 | 73 / 0 | 88 / 105 | 17 | 16.2% |
| 2 | 역순 needle (encode-needle) | 287 / 287 | 변화 0건 | 35 / 66 | 73 / 0 | 95 / 105 | 10 | 9.5% |
| 3 | 연속 12자 조각 검사 (롤링 해시) | 292 / 292 | 변화 0건 | 35 / 66 | 73 / 0 | 101 / 105 | 4 | 3.8% |

오탐·미탐은 정답(expect) 기준 분모(정상 239 · 공격 105). 세 단계 모두에서 확장 A/B의 차단·통과 판정은 기준과 한 건도 달라지지 않았다. 실행 B 오탐 73건 중 출력 스캔이 근거를 낸 건은 0단계부터 3단계까지 모두 0건이다.

## fallback-only 미탐지의 구성

| 단계 | 짧은 값 (6~7자) | 분할 전송 | 역순 변형 | base64된 짧은 값 | 다중 전송 중 인코딩 | 합계 |
|---|---|---|---|---|---|---|
| 0 | 21 | 6 | 6 | 0 | 0 | 33 |
| 1 | 0 | 6 | 7 | 2 | 2 | 17 |
| 2 | 0 | 6 | 0 | 2 | 2 | 10 |
| 3 | 0 | 0 | 0 | 2 | 2 | 4 |

- 0단계의 "짧은 값 21"에는 base64된 짧은 값 4건과 짧은 값을 역순으로 실은 1건이 포함돼 있다. 1단계에서 문턱이 내려가면서 그 5건이 각자의 형태 열로 드러났다.
- 3단계 후 남는 4건: X271, X279#2, X311, X329#2. 전부 6~7자 시크릿의 base64 인코딩본이다. base64 run 후보(16자 이상)와 디코딩 게이트(12바이트 이상)는 출처와 무관하게 유지했다.

## 4단계 — 안전 바닥 완화 규칙 (`fallbackRelaxation`, 기본 `off`)

규칙: lineage 모드에서 연결 근거가 TEMPORAL_FALLBACK뿐이고 출력 스캔·볼트 원본 재전송 검사가
아무것도 못 찾으면 통과. session 모드는 출력 스캔이 없으므로 스위치를 무시한다.
스위치는 ext 세트에만 `--relax`로 주입했고 기존 81·boundary 11은 항상 `off`다.

- npm test 298 / 298 (설정 파싱 1건 · session 무시 2건 · 속성 R1~R4 3건 추가)
- fast-check: `property.test.ts` P1~P4 (P1 5000회) 통과 · `fallback-relaxation.property.test.ts` R1~R4 (3000회) 통과
- 기존 81 · boundary 11: 변화 0건 (스위치 off)

| 실행 | 스위치 | session 오탐 / 미탐 | lineage 오탐 / 미탐 | 두 모드가 갈린 지점 |
|---|---|---|---|---|
| A (config.dev-bench.json) | off | 35 / 66 | 35 / 66 | 0 |
| A | scan-clean | 35 / 66 | 3 / 66 | 32 |
| B (config.dev-bench-ext.json) | off | 73 / 0 | 73 / 0 | 0 |
| B | scan-clean | 73 / 0 | 0 / 4 | 77 |

오탐·미탐 분모는 정답 기준(정상 239 · 공격 105). 리포트 파일: `results-ext-A.md`, `results-ext-A-relax.md`,
`results-ext-B.md`, `results-ext-B-relax.md`.

- A-relax에 남는 lineage 오탐 3건: X169, X187, X205. 셋 다 "민감값을 전송하나 세션에 비신뢰 읽기 없음"
  유형이다. 싱크 인자에 민감값 원문이 있어 출력 스캔이 잡고, 비신뢰 축은 미등록 도구의 default-deny에서
  온다. 완화 조건(스캔 무결과)에 해당하지 않으므로 완화 대상이 아니다.
- B-relax의 lineage 미탐 4건: X271, X279#2, X311, X329#2. 3단계 뒤 남아 있던 "짧은 값의 base64" 4건과
  같다.
- 기존 속성 테스트 P1(`property.test.ts`, TLA+ ReachSink의 코드판 오라클)은 스위치를 켠 설정으로 돌리면
  실패한다(스크래치 사본으로 확인, seed 347482798). fast-check가 축소한 최소 반례:
  `read_secrets` 기록(출처 기반 S, 짧은 페이로드) → 인자에 U 태그가 실린 `http_post` 평가(명시 참조·값
  매칭 없음 → 시간 폴백). 오라클(모델 미러)은 차단을 기대하고 완화는 통과시킨다. 완화가 모델의
  ExfilSafety보다 약한 규칙이기 때문이며, 모델은 아직 수정하지 않았다.

## 5단계 — 완화 base64 디코딩 집합 (12자 미만 출처 needle 전용, 지연 생성)

엄격 디코딩 집합(run ≥16자·디코딩 ≥12바이트)은 그대로 두고, 완화 집합(run ≥8자·디코딩 ≥6바이트)을
12자 미만 출처 needle이 처음 나올 때만 메모이즈 생성해 그 needle의 정확·정규화 포함검사에만 공급한다.
`output-scan.test.ts`의 "6~11자 출처 값의 base64는 미탐" 한계 테스트는 근거 주석과 함께 기대값을
탐지로 바꿨고, 내용 기반이면 여전히 미탐임을 같은 테스트에서 단언한다.

- npm test 301 / 301 (base64 완화 테스트 3건 추가)
- fast-check: P1~P4 (P1 5000회) 통과 · R1~R4 (3000회) 통과
- 기존 81 · boundary 11: 변화 0건

| 실행 | 스위치 | session 오탐 / 미탐 | lineage 오탐 / 미탐 |
|---|---|---|---|
| A | off | 35 / 66 | 35 / 66 |
| A | scan-clean | 35 / 66 | 3 / 66 |
| B | off | 73 / 0 | 73 / 0 |
| B | scan-clean | 73 / 0 | **0 / 0** |

4단계에서 남았던 B 완화 모드 미탐 4건(X271, X279#2, X311, X329#2)이 0건이 됐다. 실행 B 완화 모드에서
두 모드가 갈린 지점은 73건(오탐 73건 전부 lineage 통과, 미탐 추가 없음).

### 1MB 입력 비용 (같은 입력, 변경 전 사본 대비, 5회 평균)

| haystack | needle 구성 | 변경 전 | 변경 후 |
|---|---|---|---|
| 1MB 산문 | 출처 needle 없음 (내용 needle 21자) | 92.4ms | 92.6ms |
| 1MB 산문 | 출처 needle 12자 이상만 (3개) | 93.0ms | 91.2ms |
| 1MB 산문 | 출처 needle 12자 미만 포함 (6자·7자) | 73.6ms | 134.7ms |
| 1MB 단일문자 | 출처 needle 없음 | 33.9ms | 33.9ms |
| 1MB 단일문자 | 출처 needle 12자 이상만 | 34.4ms | 34.2ms |
| 1MB 단일문자 | 출처 needle 12자 미만 포함 | 21.7ms | 37.2ms |

완화 집합은 12자 미만 출처 needle이 있는 호출에서만 생성되며, 그 비용은 haystack의 8자 이상 영숫자
run 수에 비례한다(산문 +61ms, 단일문자 +15ms). 그 외 구성은 측정 오차 안에서 동일하다.

## 회귀 확인 방법

```bash
npm run build && npm test
BENCH_MODE=<session|lineage> BENCH_SET=<realistic|boundary> npx tsx benchmark/run-mode.ts   # 기준 JSON과 레코드 대조
npm run bench -- --set ext --label A
npm run bench -- --set ext --config benchmark/config.dev-bench-ext.json --label B
```
