/**
 * PolicyConfig 로더 단위 테스트 — 신·구 형식 정규화, 기본값, fail-closed.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SinkClass } from "@taintguard/types";
import { loadPolicyConfig } from "./config.js";

const DEV_JSON = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "config",
  "dev.json"
);

function writeTmpConfig(name: string, value: unknown): string {
  const dir = mkdtempSync(path.join(tmpdir(), "taintguard-config-"));
  const file = path.join(dir, name);
  writeFileSync(file, JSON.stringify(value));
  return file;
}

test("dev.json: 신형 키(…SourceTools/outboundSinkTools)가 정규화되어 로드된다", () => {
  const cfg = loadPolicyConfig(DEV_JSON);
  assert.equal(cfg.domain, "dev");
  assert.ok(cfg.sensitiveSourceTools.has("read_env_file"));
  assert.ok(cfg.untrustedSourceTools.has("read_github_issue"));
  assert.equal(cfg.sinks.get("push_to_remote"), SinkClass.OUTBOUND_SINK);
  assert.equal(cfg.unknownToolPolicy, "deny");
  assert.equal(cfg.sensitiveSourcePolicy, "tag_all");

  assert.ok(cfg.secretDetection);
  assert.equal(cfg.secretDetection?.bySource, true);
  assert.equal(cfg.secretDetection?.byEntropy?.minLength, 20);
  assert.ok(cfg.secretDetection?.byRegex.some((p) => p.type === "AWS_KEY"));

  assert.ok(cfg.extractionSchema);
  const typeField = cfg.extractionSchema?.fields.type;
  assert.deepEqual(typeField, { kind: "enum", values: ["bug", "feature", "question"] });
  const titleField = cfg.extractionSchema?.fields.title;
  assert.deepEqual(titleField, { kind: "string", maxLength: 80, charset: "safe-text" });
});

test("구형 키(sensitiveSources/sinks 맵)도 정규화되고, 생략된 옵션은 안전한 기본값", () => {
  const file = writeTmpConfig("legacy.json", {
    sensitiveSources: ["hr_lookup"],
    untrustedSources: ["rss_feed"],
    sinks: { webhook: "OUTBOUND_SINK", save_draft: "WRITE_INTERNAL" },
  });
  const cfg = loadPolicyConfig(file);
  assert.ok(cfg.sensitiveSourceTools.has("hr_lookup"));
  assert.equal(cfg.sinks.get("save_draft"), SinkClass.WRITE_INTERNAL);
  assert.equal(cfg.unknownToolPolicy, "deny"); // 기본값은 deny (원칙 4)
  assert.equal(cfg.secretDetection, null);
  assert.deepEqual(cfg.piiPatterns, []);
  assert.equal(cfg.extractionSchema, null);
});

test("outboundSinkTools 배열과 sinks 맵이 둘 다 있으면 병합된다", () => {
  const file = writeTmpConfig("merged.json", {
    sensitiveSourceTools: [],
    untrustedSourceTools: [],
    outboundSinkTools: ["http_post"],
    sinks: { save_draft: "WRITE_INTERNAL" },
  });
  const cfg = loadPolicyConfig(file);
  assert.equal(cfg.sinks.get("http_post"), SinkClass.OUTBOUND_SINK);
  assert.equal(cfg.sinks.get("save_draft"), SinkClass.WRITE_INTERNAL);
});

test("propagationMode: dev.json은 live, 생략 시 기본 snapshot, 그 외 값은 예외", () => {
  assert.equal(loadPolicyConfig(DEV_JSON).propagationMode, "live");

  const legacy = writeTmpConfig("prop-default.json", {
    sensitiveSources: [],
    untrustedSources: [],
    sinks: {},
  });
  assert.equal(loadPolicyConfig(legacy).propagationMode, "snapshot");

  const bad = writeTmpConfig("prop-bad.json", {
    sensitiveSourceTools: [],
    untrustedSourceTools: [],
    outboundSinkTools: [],
    propagationMode: "eager",
  });
  assert.throws(() => loadPolicyConfig(bad), /"snapshot" \| "live"/);
});

test("judgmentMode: 생략 시 기본 session(toy), dev.json은 shadow, 잘못된 값은 예외", () => {
  const legacy = writeTmpConfig("jm-default.json", {
    sensitiveSources: [],
    untrustedSources: [],
    sinks: {},
  });
  // 기본값이 session이므로 기존 사용자는 real로 바뀌지 않는다
  assert.equal(loadPolicyConfig(legacy).judgmentMode, "session");
  assert.equal(loadPolicyConfig(DEV_JSON).judgmentMode, "shadow");

  const bad = writeTmpConfig("jm-bad.json", {
    sensitiveSourceTools: [],
    untrustedSourceTools: [],
    outboundSinkTools: [],
    judgmentMode: "real",
  });
  assert.throws(() => loadPolicyConfig(bad), /"session" \| "lineage" \| "shadow"/);
});

test("fail-closed: 잘못된 형식은 전부 예외", () => {
  const base = {
    sensitiveSourceTools: [],
    untrustedSourceTools: [],
    outboundSinkTools: [],
  };

  assert.throws(
    () => loadPolicyConfig(writeTmpConfig("bad-utp.json", { ...base, unknownToolPolicy: "allow" })),
    /"deny" \| "warn"/
  );
  assert.throws(
    () =>
      loadPolicyConfig(
        writeTmpConfig("bad-regex.json", {
          ...base,
          piiPatterns: [{ type: "X", pattern: "(unclosed" }],
        })
      ),
    /정규식이 유효하지 않습니다/
  );
  assert.throws(
    () =>
      loadPolicyConfig(
        writeTmpConfig("bad-charset.json", {
          ...base,
          extractionSchema: {
            fields: { name: { kind: "string", maxLength: 10, charset: "anything-goes" } },
          },
        })
      ),
    /등록된 문자셋이 아닙니다/
  );
  assert.throws(
    () =>
      loadPolicyConfig(
        writeTmpConfig("no-sinks.json", { sensitiveSourceTools: [], untrustedSourceTools: [] })
      ),
    /"outboundSinkTools" 또는 "sinks"/
  );
  assert.throws(
    () =>
      loadPolicyConfig(
        writeTmpConfig("bad-entropy.json", {
          ...base,
          secretDetection: { byEntropy: { minLength: 0, entropyThreshold: 3.8 } },
        })
      ),
    /양의 정수/
  );
  assert.throws(
    () =>
      loadPolicyConfig(
        writeTmpConfig("bad-ssp.json", { ...base, sensitiveSourcePolicy: "tag_none" })
      ),
    /"tag_all"만 지원/
  );
});
