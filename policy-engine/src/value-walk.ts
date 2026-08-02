/**
 * 값 트리 순회 유틸 — 재귀 없는(스택오버플로 면역) 문자열 수집·치환.
 *
 * ★ 견고성(DoS 수정): 예전엔 collectStrings가 파일별 사본 3개(lineage·output-scan·
 * sanitization) + 동형 재귀 2개(detectSecrets·walkAndTokenize)로 흩어진 무가드 재귀라,
 * 순환참조는 무한재귀, 깊은 중첩(배열 ~1만·객체 ~5만 depth 실측)은 RangeError로 터졌다.
 * 이 경로는 recordToolResult/recordExternalContent(프록시 fail-safe가 "차단" 처리 →
 * 정상 깊은 데이터 오탐 + 공격자 유발 DoS)와 판정 경로 전체가 탄다. 여기 명시 스택
 * 순회로 단일화 — 깊이 무제한, 비용은 입력 노드 수에 선형.
 *
 * ★ 깊이 상한·절단을 쓰지 않는 이유(미탐 차단): 상한 D + "초과분 절단"은 어떤 D에서도
 * 우회를 연다 — 나가는 인자의 중첩 깊이는 공격자 제어라, D+1 깊이에 민감값을 숨기면
 * 출력스캔·볼트 원본 매칭이 절단 탓에 못 보고 통과한다("상한 밑에 숨기면 통과").
 * 계보 쪽도 절단되면 토큰이 빠져 VALUE_MATCH 부모 연결이 끊긴다(오염 미탐).
 * 절단 없는 선형 순회는 이 우회가 성립 자체가 안 된다.
 *
 * ★ WeakSet/Map 방문가드: 순환(같은 객체 재방문 → 정보손실 0)과 공유참조 DAG
 * (같은 객체를 여러 곳이 참조 — 재귀면 방문 수가 지수로 폭발하는 증폭 DoS)를 함께
 * 차단한다. 문자열은 원시값이라 가드 대상이 아니므로 항상 수집된다. JSON 전송 데이터
 * (프록시로 유입되는 전부)는 순환·공유참조를 표현할 수 없어, 수집 결과가 기존 재귀
 * 구현과 순서까지 비트 단위로 동일하다.
 */

/** 값 트리의 모든 문자열을 깊이우선(pre-order, 기존 재귀와 동일 순서)으로 수집한다. */
export function collectStrings(value: unknown): string[] {
  const out: string[] = [];
  const seen = new WeakSet<object>();
  const stack: unknown[] = [value];
  while (stack.length > 0) {
    const v = stack.pop();
    if (typeof v === "string") {
      out.push(v);
    } else if (Array.isArray(v)) {
      if (seen.has(v)) continue;
      seen.add(v);
      for (let i = v.length - 1; i >= 0; i--) stack.push(v[i]);
    } else if (typeof v === "object" && v !== null) {
      if (seen.has(v)) continue;
      seen.add(v);
      const values = Object.values(v);
      for (let i = values.length - 1; i >= 0; i--) stack.push(values[i]);
    }
  }
  return out;
}

/** 부모 컨테이너의 한 자리(key)에 변환 결과를 써 넣기 위한 작업 단위 */
interface MapSlot {
  src: unknown;
  dst: Record<string, unknown> | unknown[];
  key: string | number;
}

/**
 * 값 트리의 문자열마다 map을 적용한 사본을 만들고, 치환된 문자열들을 함께 돌려준다
 * (tokenizePII의 재검증용). 컨테이너는 전부 새로 만들며 원본은 변형하지 않는다.
 * memo(입력→출력)가 순환·공유참조의 모양을 출력에 그대로 보존한다 — 순환 입력도
 * 순환 출력이 될 뿐 무한루프 없음.
 */
export function mapValueStrings(
  root: unknown,
  map: (s: string) => string
): { value: unknown; strings: string[] } {
  const strings: string[] = [];
  const memo = new Map<object, unknown>();
  const holder: Record<string, unknown> = {};
  const stack: MapSlot[] = [{ src: root, dst: holder, key: "v" }];
  while (stack.length > 0) {
    const { src, dst, key } = stack.pop()!;
    let replacement: unknown;
    if (typeof src === "string") {
      replacement = map(src);
      strings.push(replacement as string);
    } else if (Array.isArray(src)) {
      if (memo.has(src)) {
        replacement = memo.get(src);
      } else {
        const out = new Array<unknown>(src.length);
        memo.set(src, out);
        for (let i = src.length - 1; i >= 0; i--) stack.push({ src: src[i], dst: out, key: i });
        replacement = out;
      }
    } else if (typeof src === "object" && src !== null) {
      if (memo.has(src)) {
        replacement = memo.get(src);
      } else {
        const out: Record<string, unknown> = {};
        memo.set(src, out);
        const entries = Object.entries(src);
        for (let i = entries.length - 1; i >= 0; i--) {
          stack.push({ src: entries[i][1], dst: out, key: entries[i][0] });
        }
        replacement = out;
      }
    } else {
      replacement = src; // number/boolean/null 등은 그대로
    }
    (dst as Record<string | number, unknown>)[key] = replacement;
  }
  return { value: holder.v, strings };
}
