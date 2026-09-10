#!/usr/bin/env python3
"""
AgentDojo(MIT) 정답 트레이스 → JSON export.

목적: 논문 §4 평가 세트를 자체 합성 81개에서 외부 벤치(AgentDojo[10]) 기반으로
확장하기 위한 1단계. AgentDojo의 각 task는 LLM 없이 결정론적 ground_truth()
(= 도구 호출 시퀀스)를 제공하므로, API 키·비용 없이 트레이스를 뽑을 수 있다.

- user task     → 정상 흐름(공격자 주입 없음). 마지막 싱크 호출의 정답 = 통과(pass).
- injection task→ 공격 흐름(주입된 지시대로 외부 유출). 정답 = 차단(block).
- injection vector→ 주입이 어느 필드/도구 결과에 실리는지 → UNTRUSTED_ORIGIN 판별 근거.

주의: 이 스크립트는 트레이스만 덤프한다. 우리 엔진 태그(sink/sensitive/untrusted)
매핑과 Scenario 번역은 다음 단계(별도 파일)에서 문서화하며 수행한다. 즉 이건
"AgentDojo를 에이전트까지 end-to-end로 돌린 것"이 아니라 "정답 트레이스를 판정
지점으로 번역하기 위한 원천 데이터 추출"이다. 논문에도 정확히 그렇게 기술한다.

실행:
    python export-agentdojo.py           # 모든 suite → agentdojo-export.json
"""

import json
import sys
from pathlib import Path

from agentdojo.task_suite.load_suites import get_suites

OUT = Path(__file__).parent / "agentdojo-export.json"


def calls_to_list(calls):
    """ground_truth()가 돌려준 FunctionCall 리스트를 순수 dict로."""
    out = []
    for c in calls:
        out.append({"function": c.function, "args": dict(c.args)})
    return out


def main():
    suites = get_suites("v1")
    export = {"benchmark": "agentdojo", "version": "v1", "license": "MIT", "suites": {}}
    totals = {"user_tasks": 0, "injection_tasks": 0}

    for sname, suite in suites.items():
        # 기본 주입 벡터를 심은 pre-environment (ground_truth 재료)
        inj_defaults = suite.get_injection_vector_defaults()
        env = suite.load_and_inject_default_environment(inj_defaults)

        s_rec = {
            "tools": [getattr(f, "name", getattr(f, "__name__", "?")) for f in suite.tools],
            "injection_vectors": dict(inj_defaults),  # key -> 주입된 문자열
            "user_tasks": [],
            "injection_tasks": [],
        }

        for k, t in suite.user_tasks.items():
            try:
                gt = calls_to_list(t.ground_truth(env))
            except Exception as e:  # 일부 task는 env 의존 → 실패 시 기록만
                gt = []
                gt_err = repr(e)
            else:
                gt_err = None
            s_rec["user_tasks"].append({
                "id": k,
                "prompt": getattr(t, "PROMPT", None),
                "ground_truth": gt,
                "ground_truth_error": gt_err,
            })

        for k, t in suite.injection_tasks.items():
            try:
                gt = calls_to_list(t.ground_truth(env))
                gt_err = None
            except Exception as e:
                gt, gt_err = [], repr(e)
            s_rec["injection_tasks"].append({
                "id": k,
                "goal": getattr(t, "GOAL", None),
                "ground_truth": gt,
                "ground_truth_error": gt_err,
            })

        totals["user_tasks"] += len(s_rec["user_tasks"])
        totals["injection_tasks"] += len(s_rec["injection_tasks"])
        export["suites"][sname] = s_rec

    export["totals"] = totals
    OUT.write_text(json.dumps(export, ensure_ascii=False, indent=2), encoding="utf-8")

    # 요약을 stderr로 (stdout은 깨끗하게)
    print(f"[export] wrote {OUT}", file=sys.stderr)
    for sname, s in export["suites"].items():
        nu = len(s["user_tasks"])
        ni = len(s["injection_tasks"])
        print(f"  {sname:10s} user={nu:3d}  injection={ni:3d}  tools={len(s['tools'])}", file=sys.stderr)
    print(f"  {'TOTAL':10s} user={totals['user_tasks']:3d}  injection={totals['injection_tasks']:3d}", file=sys.stderr)


if __name__ == "__main__":
    main()
