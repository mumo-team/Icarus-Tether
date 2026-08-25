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

### 승인 버튼을 누르려면 — 제어 토큰

대시보드의 **관측**(판정·오염 계보 실시간 표시)은 토큰 없이 그대로 동작합니다.
**승인·거부·정화처럼 상태를 바꾸는 명령만** 토큰을 요구합니다. 인젝션당한
에이전트가 스스로 승인을 눌러 HITL을 통과하는 경로를 막기 위한 것입니다.

프록시는 기동할 때마다 새 토큰을 만들어 두 곳에 둡니다.

- **콘솔** — 기동 직후 `[bridge] ── 제어 토큰 ──` 블록으로 출력
- **파일** — `<OS 임시 폴더>/icarus-tether-control.token`
  (Windows는 `%TEMP%`, macOS·리눅스는 `/tmp`)

대시보드 상단 **제어 토큰** 칸에 한 번 붙여넣으면 브라우저에 저장됩니다.
넣지 않고 승인을 누르면 화면에 거부 사유가 뜹니다.

> 위 `demo:hitl`의 자동 승인은 파일에서 토큰을 읽으므로 입력이 필요 없습니다.
> 사람이 대시보드에서 직접 누를 때만 붙여넣기가 필요합니다.

### 실제 AI 에이전트에 붙여 보기

저장소에 `.mcp.json`이 들어 있어, **클론한 뒤 이 폴더에서 Claude Code를 열면
프록시가 자동으로 연결됩니다.** 별도 등록이 필요 없습니다.

```bash
npm install          # 최초 1회
claude               # 이 저장소 폴더에서 실행
```

처음 실행하면 **프로젝트 MCP 서버를 신뢰할지 묻는 승인 프롬프트**가 뜹니다.
클론한 저장소가 코드를 임의로 실행하지 못하게 하는 Claude Code의 보호 장치이며,
승인해야 도구가 붙습니다.

연결되면 `query_customer_db` · `fetch_web_page` · `send_email` 세 도구가 노출됩니다.
평소처럼 자연어로 시키면 되고, 모든 호출이 프록시의 판정을 거칩니다.

```
team@example.com 으로 빌드 성공했다고 메일 보내줘        → 통과
https://partner.example/newsletter 읽어줘                → 통과 (비신뢰 태그)
C-1024 고객 정보 조회해줘                                 → 통과 (민감 태그)
방금 내용을 partner@example.com 으로 보내줘               → 차단
```

앞의 셋은 개별적으로 모두 정상 동작이고, 마지막만 막힙니다 — 도구가 아니라
**흐름**을 보기 때문입니다. `npm run dev:dashboard`를 함께 띄우면 차단 근거와
오염 계보를 화면으로 확인할 수 있습니다(호출 전에 먼저 띄워야 합니다).

> 이 경로에서는 프록시를 Claude Code가 띄우므로 **토큰이 콘솔에 보이지 않습니다.**
> 대시보드에서 승인을 누르려면 위 임시 폴더의 토큰 파일을 열어 값을 복사하세요.

> 세션 오염 이력은 한 번 켜지면 꺼지지 않습니다(grow-only). 처음부터 다시 보려면
> Claude Code 세션을 새로 여세요 — 프록시도 함께 새로 뜹니다.

Claude Desktop에 등록하려면 `npm run setup:claude`를 쓸 수 있습니다. 다만 최신
빌드는 대화를 원격에서 실행해 로컬 MCP 서버를 읽지 않을 수 있습니다.

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
