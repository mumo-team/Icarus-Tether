type PiiPattern = [RegExp, string];

const PATTERNS: PiiPattern[] = [
  [/\b\d{3}-\d{2}-\d{4}\b/g, "[SSN_REDACTED]"],                    // 미국식 SSN
  [/\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g, "[EMAIL_REDACTED]"],            // 이메일
  [/\b01[016789]-?\d{3,4}-?\d{4}\b/g, "[PHONE_REDACTED]"],          // 한국 휴대폰
  [/\b\d{6}-[1-4]\d{6}\b/g, "[RRN_REDACTED]"],                      // 한국 주민등록번호
];

export function maskPii(text: string): string {
  return PATTERNS.reduce((acc, [pattern, replacement]) => acc.replace(pattern, replacement), text);
}