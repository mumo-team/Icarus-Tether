# AgentDojo 기반 평가 세트 확장 (외부 벤치 일반화)

논문 §4 평가를 자체 합성 81 집중 세트에서 외부 벤치마크 **AgentDojo**
(NeurIPS 2024, MIT)로 확장한다. AgentDojo 각 태스크는 LLM 없이 결정론적 정답
트레이스(`ground_truth`)를 주므로 **API 비용 없이($0)** 판정 지점으로 번역한다.

이 세트의 역할은 **공격 커버리지·일반화**다: banking·workspace·travel·slack
4개 도메인에서 lethal trifecta가 성립하는 **공격 294건을 미탐 0%로 차단**.
session↔lineage 모드 차이(과차단 감소)는 이 세트로 비교하지 않는다 — 이유는 아래.

## 파일

| 파일 | 역할 | 커밋? |
|---|---|---|
| `export-agentdojo.py` | AgentDojo 정답 트레이스 → JSON 덤프 | ✅ |
| `mapping.json` | 도구 3축 분류(민감/비신뢰/싱크). UNTRUSTED는 마커주입 실행으로 자동 판별 | ✅ |
| `generate-scenarios.py` | 트레이스+매핑 → 판정 지점 `scenarios-agentdojo.json` | ✅ |
| `run-mode-adojo.ts` | 정책 엔진(무수정) import → session/lineage 채점 | ✅ |
| `agentdojo-export.json` | 덤프(재생성 가능) | 선택 |
| `scenarios-agentdojo.json` | 생성된 판정 지점(~2MB, 재생성 가능) | 선택 |
| `result-session.json`, `result-lineage.json` | 채점 결과 | ✅ |

> AgentDojo 자체 코드·venv·시크릿은 **커밋하지 않는다**(MIT 의존성으로 설치).
> 파생 데이터는 AgentDojo(MIT)에서 파생됨을 밝힌다.

## 재현

```bash
python3 -m venv venv && ./venv/bin/pip install agentdojo
./venv/bin/python export-agentdojo.py
./venv/bin/python generate-scenarios.py
# 저장소 루트에서(tsx가 워크스페이스 패키지를 찾도록):
BENCH_MODE=session npx tsx docs/submission/eval/run-mode-adojo.ts > docs/submission/eval/result-session.json
BENCH_MODE=lineage npx tsx docs/submission/eval/run-mode-adojo.ts > docs/submission/eval/result-lineage.json
```

## 결과 (2026-09 기준)

| 도메인 | 공격 | 정상 | 미탐(FN) |
|---|---|---|---|
| workspace | 146 | 6 | 0% |
| banking | 100 | 7 | 0% |
| travel | 40 | 2 | 0% |
| slack | 8 | 17 | 0% |
| **합계** | **294** | **32** | **0/294 (0.0%)** |

session·lineage 동일. 전체 326 판정 지점.

## 왜 FP(과차단)는 이 세트로 비교하지 않는가

AgentDojo `ground_truth`의 싱크 인자는 읽은 원문 토큰을 그대로 담지 않는다
(요약·대표값). lineage의 값 대응(VALUE_MATCH)이 걸릴 앵커가 없어 항상 보수적
안전 바닥(TEMPORAL_FALLBACK)으로 떨어지고, 결과적으로 lineage가 session과 동일하게
행동한다. 따라서 이 세트의 FP 수치는 엔진의 실사용 과차단률이 아니라 바닥 아티팩트다.
모드 FP 비교(18.5%→9.3%)는 값 전파 구조를 갖춘 기존 81 집중 세트에서 측정한다.
