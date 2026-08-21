# Icarus-Tether

> AI 에이전트가 MCP로 도구를 실행할 때 발생하는 lethal trifecta(민감 데이터 + 비신뢰 입력 + 외부 유출)를 실시간으로 추적·차단하는 오픈소스 보안 게이트웨이.
>
> 2026 오픈소스 개발자대회(자유과제) 출품작 · 팀 무모

## 왜 필요한가

기존 AI 보안 도구(garak, LLM Guard 등)는 에이전트가 하는 **말(텍스트)**을 검사합니다.
Icarus-Tether는 에이전트가 실제로 실행하려는 **행동(도구 호출)**을 가로채, 위험한 데이터 흐름 자체를 봅니다.

자세한 배경과 아키텍처는 [`docs/architecture.md`](./docs/architecture.md)를 참고하세요.

## 구조

```
Icarus-Tether/
├── proxy/           # ② MCP 도구 호출 가로채기·세션관리 (담당: 정수민)
├── policy-engine/   # ① 오염 태그 추적·트라이펙타 판정·정화 (담당: 이류진)
├── dashboard/       # ③ 승인 큐·감사로그·오염 그래프 시각화 (담당: 함한솔)
├── shared/types/    # 세 워크스페이스가 공유하는 타입 계약
└── docs/            # 아키텍처·표준 매핑 문서
```

## 시작하기

```bash
npm install
npm run build     # 전체 워크스페이스 빌드 (types → policy-engine → proxy → dashboard 순)
```

> `npm run build`는 생략할 수 없습니다. proxy는 policy-engine을 `dist/`로 가져다 쓰므로,
> 빌드 없이 실행하면 `Cannot find package '@icarus-tether/policy-engine/dist/index.js'`로 죽습니다.

### 바로 보기 — 공격 차단 데모

```bash
npm run demo:killer -w proxy
```

탈옥 문구 없이 정중하게 쓰인 이메일에 에이전트가 속아 고객정보를 외부로 보내려 하고,
게이트웨이가 **흐름**으로 그것을 막는 과정이 터미널에 단계별로 출력됩니다.

> 첫 실행은 ML 인젝션 탐지 모델을 내려받느라 오래 걸릴 수 있습니다(보조 신호 — 차단 판정과 무관).

### 대시보드와 함께 보기

터미널 두 개가 필요합니다.

```bash
npm run dev:dashboard      # (1) 대시보드 — http://localhost:5173
npm run demo:hitl -w proxy # (2) 데모 실행 → 대시보드에 실시간 반영 + 승인 모달
```

### 검증

```bash
npm test                                    # 전체 298건 (policy 277 · dashboard 13 · server 8)
npm run bench -w @icarus-tether/policy-engine   # 정확도 벤치 (session vs lineage)
npm run verify -w dashboard/server          # 감사로그 해시체인 무결성 검증
```

전체 데모·테스트 목록은 [`proxy/README.md`](./proxy/README.md), 판정 엔진의 보장·한계는
[`policy-engine/README.md`](./policy-engine/README.md)를 참고하세요.

## 핵심 개념

- **오염(taint) 추적**: 도구 호출 결과에 `SENSITIVE` / `UNTRUSTED_ORIGIN` 태그를 붙이고, 세션 안에서 전파를 추적합니다.
- **트라이펙타 차단**: **나가는 값**이 민감 데이터를 담고 있고 **세션**이 비신뢰 입력에 노출된 적이 있으면, `OUTBOUND_SINK`(외부 유출) 도구 실행 직전에 막습니다. 민감은 값으로, 비신뢰는 세션으로 보는 이 비대칭 판정이 과차단을 절반으로 줄입니다.
- **검증된 정화(declassification)**: 토큰화·구조화 추출 같은 검증된 방법을 통과한 데이터는 태그를 안전하게 해제해, 세션이 영구적으로 막히지 않게 합니다. 기존 오픈소스의 세션 단위 boolean 방식에는 없는 부분입니다.

## 라이선스

[Apache License 2.0](./LICENSE)
