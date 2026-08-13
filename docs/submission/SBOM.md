# SBOM — 소프트웨어 자재명세서

**프로젝트:** Icarus-Tether (MCP 행동 오염흐름 추적 보안 게이트웨이)
**프로젝트 라이선스:** Apache-2.0
**기계판독 SBOM:** [`SBOM.cyclonedx.json`](./SBOM.cyclonedx.json) — CycloneDX 1.5, 총 253개 컴포넌트(직접+전이 의존성 전체)
**생성 방법:** `npm sbom --sbom-format cyclonedx` (npm 11.6.1)

## 라이선스 요약

모든 의존성이 **MIT 또는 Apache-2.0**(허용적 라이선스)이다. 카피레프트(GPL/AGPL 등) 의존성은 없으며, Apache-2.0 프로젝트로 배포하는 데 라이선스 충돌이 없다.

| 라이선스 | 개수(직접 의존성 기준) |
|---|---|
| MIT | 다수 (React, MCP SDK, ws, vite, tsx, express 등) |
| Apache-2.0 | typescript, @huggingface/transformers |

## 직접 의존성 (워크스페이스별)

> 내부 워크스페이스(`@icarus-tether/*`)는 자체 소스이므로 외부 의존성에서 제외.

### 런타임 의존성 (배포에 포함)

| 패키지 | 버전 | 라이선스 | 용도 | 사용 파트 |
|---|---|---|---|---|
| `@modelcontextprotocol/sdk` | 1.29.0 | MIT | MCP 프로토콜(Server/Client/전송) | 프록시 |
| `ws` | 8.21.0 | MIT | 대시보드 실시간 WebSocket(7331) | 프록시(브리지) |
| `@huggingface/transformers` | 3.8.1 | Apache-2.0 | ML 프롬프트 인젝션 탐지(보조 신호) — [AI 명세서](./AI-model-spec.md) 참조 | 프록시 |
| `react` / `react-dom` | 18.3.1 | MIT | 대시보드 UI | 대시보드 |
| `@xyflow/react` | 12.11.2 | MIT | 오염 계보 그래프(DAG) 시각화 | 대시보드 |

### 개발 의존성 (빌드·테스트 전용, 배포 미포함)

| 패키지 | 버전 | 라이선스 | 용도 |
|---|---|---|---|
| `typescript` | 5.9.3 | Apache-2.0 | 타입 검사·컴파일 |
| `tsx` | 4.23.0 | MIT | TypeScript 직접 실행(데모·테스트) |
| `vite` / `@vitejs/plugin-react` | 5.4.21 / 4.7.0 | MIT | 대시보드 번들러 |
| `fast-check` | 4.9.0 | MIT | 속성 기반 테스트(퍼징) — 엔진·프록시 |
| `express` | 5.2.1 | MIT | Phase 1 HTTP 다운스트림 데모 서버(테스트) |
| `cross-env` | 7.0.3 | MIT | 크로스플랫폼 환경변수(데모 스크립트) |
| `@types/*` | — | MIT | 타입 정의 |

## 특이사항

- **정책 엔진(핵심 두뇌)의 런타임 외부 의존성은 0개** — 내부 `@icarus-tether/types`만 사용하고, 판정은 Node 표준 라이브러리(`node:crypto` 등)만으로 100% 결정론 코드로 수행한다. (AI/LLM·네트워크 호출 없음)
- **유일한 AI/ML 의존성**은 프록시의 `@huggingface/transformers`(보조 인젝션 탐지 신호)이며, 핵심 보안 판정은 이에 의존하지 않는다. 상세는 [AI 모델 명세서](./AI-model-spec.md).
- 형식검증에 사용하는 TLA+ 도구(`tla2tools.jar`)는 개발 도구로, 저장소/배포에 포함하지 않는다.
