# Icarus-Tether · 표준 매핑 (Standard Mapping)
 
> 우리 기능이 국제 보안 표준의 어떤 위협에 대응하는지 정리.
> 목적: "우리 생각에 위험해서"가 아니라 "공인 표준이 정의한 위협에 대응함"을 증명 (서면 심사·발표용).
> 기준 표준: OWASP Top 10 for LLM Applications 2025, OWASP Top 10 for Agentic Applications 2026,
>           CoSAI (Coalition for Secure AI), MITRE ATLAS.
 
---
 
## 📌 요약 — 한눈에
 
우리(Icarus-Tether)는 **"lethal trifecta"(민감🔴 + 비신뢰🔵 + 외부유출➡️의 수렴)를 값 단위로
결정론적 차단**하는 MCP 보안 게이트웨이다. 이는 아래 표준들이 정의한 **최상위 위협들에 직접 대응**한다:
 
```
OWASP LLM01 (프롬프트 인젝션)     ← 2년 연속 1위 위협
OWASP LLM02 (민감정보 유출)       ← 우리가 막는 것의 본체
OWASP ASI01 (에이전트 목표 탈취)   ← Agentic 1위
OWASP ASI02 (도구 오용)           ← Agentic 2위
```
 
**핵심 주장:** 이 위협들은 "AI에게 물어봐서" 막을 수 없다(그 AI가 조작 대상이므로).
우리는 **AI 호출 0의 결정론 게이트**로 데이터 흐름을 추적해 차단한다.
(코드 검증: policy-engine 런타임 의존성에 AI SDK·네트워크 클라이언트 없음, 판정 경로 전체에 외부 AI/LLM 호출 0건 — 의존성·정적분석 양쪽으로 확인됨.)
 
---
 
## 1. OWASP Top 10 for LLM Applications (2025)
 
> 2025 최신판. LLM01(프롬프트 인젝션)이 2판 연속 1위. MCP·에이전트 환경 반영.
 
| 표준 위협 | 우리 대응 | 어떻게 |
|---|---|---|
| **LLM01: Prompt Injection** | ✅ 핵심 대응 | 비신뢰 소스(웹·이슈 등)에 숨은 악성 지시가 AI를 조작해도, 그 결과 데이터 흐름을 값 단위로 추적해 **유출 시점에 결정론 차단**. 인젝션 자체를 "탐지"하려 하지 않고(우회 가능), 인젝션이 노리는 **행동(민감+비신뢰의 외부 전송)을 차단**. (보조: 인젝션 탐지 AI 모델을 **센서로만** 병용 — 점수를 대시보드에 표시할 뿐 판정에는 관여하지 않아 결정론 원칙 유지.) |
| **LLM02: Sensitive Information Disclosure** | ✅ 핵심 대응 | 민감(SENSITIVE) 태그를 출처 기반으로 부여하고, 민감 유출은 값-계보로("실제로 나가는가"), 비신뢰 노출은 세션-존재로 판정(비대칭 위협 모델). 정화(토큰화·구조화추출)로 검증된 해제만 허용(실제 변경 게이트). |
| **LLM05: Improper Output Handling** | 🔶 부분 | LLM 출력을 "비신뢰 데이터"로 취급하는 원칙과 정합(우리는 도구 결과를 UNTRUSTED_ORIGIN으로 태그). 다만 출력 세탁(인코딩) 대응은 향후 출력 스캔 계층 필요(알려진 한계). |
| **LLM06: Excessive Agency** | ✅ 대응 | 유출 행동(민감+비신뢰가 외부 싱크로 수렴)에 대해 HITL(사람 승인) 게이트 + 결정론 차단. (일반 파괴적 행동은 미분류 도구 default-deny로 보수 차단.) |
| **LLM08: Vector/Embedding Weaknesses** | ⬜ 범위 밖 | RAG 벡터 보안은 우리 범위 아님. |
 
---
 
## 2. OWASP Top 10 for Agentic Applications (2026)
 
> 2025년 12월 발표된 **최초의 에이전트 특화 peer-reviewed 프레임워크** (ASI01~ASI10).
> NIST·Microsoft·NVIDIA 등이 참조. **우리 주제와 가장 정합도 높음.**
 
| 표준 위협 | 우리 대응 | 어떻게 |
|---|---|---|
| **ASI01: Agent Goal Hijack** | ✅ 핵심 대응 | 공격자가 자연어 지시를 조작해 에이전트 목표를 탈취해도(예: "고객정보를 attacker에게 보내"), 그 탈취된 목표가 **실제 행동(외부 유출)으로 이어지는 지점을 차단**. 목표 탈취를 "판단"으로 막지 않고 "행동"으로 막음. |
| **ASI02: Tool Misuse & Exploitation** | ✅ 핵심 대응 | 정상 도구(send_email 등)를 조작된 파라미터·도구 체인으로 오용하는 걸 차단. 특히 **tool chain manipulation**(순차 도구 호출로 유출 달성)을 값 단위 계보 추적으로 잡음 — 같은 도구가 데이터 흐름에 따라 통과/차단됨. |
| **ASI03: Identity & Privilege Abuse** | 🔶 부분 | 세션 단위 권한 경계. HITL로 고위험 행동 승인. (교차 세션 방어는 알려진 한계.) |
| **ASI06: Memory/Context Poisoning** | 🔶 부분 | 세션 오염 상태를 결정론적으로 추적(오염된 컨텍스트가 판정에 영향). 다만 장기 메모리 포이즌은 범위 밖. |
| **ASI07: Insecure Inter-Agent Communication** | ⬜ 향후 | 멀티에이전트 오염 추적은 로드맵 TIER 3. |
 
> ★ ASI02 관련: OWASP는 "Intent Gate"(고위험·비가역 행동에 2차 검증)를 권고한다.
> 우리 HITL 게이트 + 결정론 trifecta 차단이 정확히 이 Intent Gate 역할이다.
 
---
 
## 3. CoSAI (Coalition for Secure AI)
 
> CoSAI = OASIS Open Project. 2026.1 발표한 **MCP Security taxonomy** (Workstream 4:
> "Secure Design Patterns for Agentic Systems"). Google·IBM·Microsoft·NVIDIA 등 참여.
 
| 프레임워크 | 우리 대응 |
|---|---|
| **MCP Security (Workstream 4)** | ✅ MCP 프로토콜 계층에서 도구 호출을 가로채 정책 판정. CoSAI가 다루는 "프로토콜 인증부터 guardrail·enforcement까지"의 enforcement 계층에 해당. 도구 결과 오염 전파를 값 단위로 추적. |
| **Secure-by-Design Agentic 원칙** (2025.7) | ✅ CoSAI 원칙 "에이전트는 bounded·resilient해야 하고, 권한 경계는 문서가 아닌 기술적 통제로 강제"와 정합 — 우리는 정책을 결정론 코드로 강제(문서가 아닌 enforcement). |
| **거버넌스·관측성** | ✅ 해시체인 감사 로그(각 항목에 직전 항목 signature를 prevHash로 엮어 편집·삭제·재정렬 시 체인 파손 탐지 — verify-audit-log.ts), 판정별 explanation, 섀도 로그로 투명성 제공. (HMAC 키 기반 서명·영속화는 향후 보강.) |
 
---
 
## 4. MITRE ATLAS (참고)
 
> ATLAS = Adversarial Threat Landscape for AI Systems (MITRE, ATT&CK의 AI판). 정확한 기법 코드로 매핑.
 
| 전술/기법 (정확 코드) | 우리 대응 |
|---|---|
| **AML.T0051 LLM Prompt Injection** (Initial Access) | ✅ 인젝션의 결과 행동을 차단 (LLM01과 동일 논리). |
| **AML.T0054 Indirect Prompt Injection** | ✅ 외부 데이터(웹·이슈)에 숨은 지시 = 우리가 막는 핵심 벡터. |
| **AML.T0086 Exfiltration via AI Agent Tool Invocation** | ✅ 연결된 도구로 데이터를 빼내는 것 = trifecta의 X축(외부 유출) 차단. |
| **AML.T0110 AI Agent Tool Poisoning** | 🔶 도구 결과 오염을 UNTRUSTED로 태그해 전파 추적. |
 
**실제 사례 (우리 시나리오와 동일):**
- **EchoLeak (CVE-2025-32711)**: Microsoft Copilot에서 프롬프트 인젝션 + 데이터 유출이
  결합된 zero-click 공격. 정확히 우리가 막는 "인젝션→민감데이터 외부 유출" 흐름.
  → OWASP ASI01(Goal Hijack) 문서도 이 사례를 인용. 우리 데모(웹 인젝션→고객정보 유출)와 동형.
---
 
## 5. 우리 접근의 차별점 — "표준이 어렵다고 한 것"을 어떻게 푸는가
 
표준들이 공통적으로 지적하는 근본 난제:
 
> **"에이전트는 정상 지시와 악성 페이로드를 신뢰성 있게 구분하지 못한다"**
> (OWASP ASI01, LLM01 공통 — 명령과 데이터가 같은 채널)
 
**대부분의 방어는 "구분을 더 잘하려" 한다** (탐지 모델, 프롬프트 필터).
→ 근데 이건 확률적이라 우회 가능 (OWASP도 "fool-proof 방법 없음" 명시).
 
**우리 접근은 다르다 — "구분"이 아니라 "행동 차단":**
```
인젝션이 성공했는지 판단하지 않는다 (그건 조작 가능)
→ 대신 "민감+비신뢰가 외부로 나가는가"라는 행동을 결정론으로 차단
→ 인젝션이 성공해도, 그 목표(유출)를 실행하는 순간 막힌다
```
 
이것이 표준들이 권고하는 **"Intent Gate"(ASI02)** 와 **"결정론적 통제"(LLM06 완화)** 의 구체적 구현이다.
 
**AI 탐지 모델과의 관계 (다층 방어):** 우리도 인젝션 탐지 AI(DeBERTa 계열)를 두지만 **센서로만** 쓴다 — 탐지 점수는 대시보드에 표시할 뿐, 차단/허용 판정에는 관여하지 않는다. "AI를 참고하되 AI에 의존하지 않는다": 확률적 탐지가 놓치거나 조작돼도 결정론 게이트가 최종 방어선이다. 이는 표준의 "다층 방어" 권고에 부합하면서도 "판정은 AI 호출 0"이라는 핵심 불변을 지킨다.
 
---
 
## 6. 정직한 커버리지 (한계 명시)
 
표준 전체를 다 막는다고 주장하지 않는다. 우리가 **직접 대응**하는 것과 **범위 밖·향후**를 구분:
 
```
✅ 직접 대응: LLM01, LLM02, LLM06 / ASI01, ASI02
🔶 부분 대응: LLM05, ASI03, ASI06
⬜ 향후·범위밖: LLM08(벡터), ASI07(멀티에이전트), 장기메모리 포이즌
   + 알려진 한계: 인코딩 세탁(출력 스캔 계층 필요), 교차 세션
   + 향후 보강: 감사 로그 HMAC 키 기반 서명 (현재 해시체인 무결성 검증까지 구현 — 변조 탐지 O, 위조 방지는 향후), 
     일반 파괴적 행동 게이트 (현재는 유출 행동만 HITL, 파괴적 행동은 default-deny 보수차단)
```
 
이 정직한 구분 자체가 "우리는 무엇을 막고 무엇을 못 막는지 정확히 안다"는 성숙도의 근거다.
 
---
 
## 참고 (인용 표준 출처)
 
- OWASP Top 10 for LLM Applications 2025 (genai.owasp.org)
- OWASP Top 10 for Agentic Applications 2026 (2025.12 발표, genai.owasp.org)
- CoSAI — Coalition for Secure AI
- MITRE ATLAS (atlas.mitre.org)
> ※ 표준은 계속 업데이트되므로, 발표·제출 직전 최신 버전·항목 번호 재확인 권장.