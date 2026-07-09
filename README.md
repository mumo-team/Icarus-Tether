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
├── proxy/           # ② MCP 도구 호출 가로채기·세션관리 (담당: A)
├── policy-engine/   # ① 오염 태그 추적·트라이펙타 판정·정화 (담당: B)
├── dashboard/       # ③ 승인 큐·감사로그·오염 그래프 시각화 (담당: C)
├── shared/types/    # 세 워크스페이스가 공유하는 타입 계약
└── docs/            # 아키텍처·표준 매핑 문서
```

## 시작하기

```bash
npm install
npm run build --workspace=@icarus-tether/types   # 공유 타입 먼저 빌드

npm run dev:proxy       # 프록시 개발 서버
npm run dev:policy      # 정책 엔진 개발 서버
npm run dev:dashboard   # 대시보드 (Vite, http://localhost:5173)
```

## 핵심 개념

- **오염(taint) 추적**: 도구 호출 결과에 `SENSITIVE` / `UNTRUSTED_ORIGIN` 태그를 붙이고, 세션 안에서 전파를 추적합니다.
- **트라이펙타 차단**: 두 태그가 모두 붙은 데이터가 `OUTBOUND_SINK`(외부 유출) 도구로 나가려 하면 실행 직전 차단합니다.
- **검증된 정화(declassification)**: 토큰화·구조화 추출 같은 검증된 방법을 통과한 데이터는 태그를 안전하게 해제해, 세션이 영구적으로 막히지 않게 합니다. 기존 오픈소스의 세션 단위 boolean 방식에는 없는 부분입니다.

## 라이선스

[Apache License 2.0](./LICENSE)
