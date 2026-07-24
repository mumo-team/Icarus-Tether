/**
 * ToolRegistry — 하위 호환 뷰.
 *
 * 설정의 단일 소스는 config.ts(PolicyConfig)로 이동했다. 이 모듈은 기존
 * 소비자(테스트 포함)를 위해 "도구 분류 세 가지"만 투영해서 돌려주는
 * thin wrapper다. 새 코드는 getPolicyConfig()를 직접 쓰는 것을 권장.
 */

import { SinkClass } from "@icarus-tether/types";
import { loadPolicyConfig } from "./config.js";

export interface ToolRegistry {
  sensitiveSources: ReadonlySet<string>;
  untrustedSources: ReadonlySet<string>;
  sinks: ReadonlyMap<string, SinkClass>;
}

/**
 * 설정 파일에서 도구 분류를 읽는다. 구형(sensitiveSources/sinks 맵)·
 * 신형(sensitiveSourceTools/outboundSinkTools 배열) 키를 모두 수용하며,
 * 파일이 없거나 형식이 틀리면 예외(fail-closed).
 */
export function loadToolRegistry(filePath?: string): ToolRegistry {
  const cfg = filePath === undefined ? loadPolicyConfig() : loadPolicyConfig(filePath);
  return {
    sensitiveSources: cfg.sensitiveSourceTools,
    untrustedSources: cfg.untrustedSourceTools,
    sinks: cfg.sinks,
  };
}

