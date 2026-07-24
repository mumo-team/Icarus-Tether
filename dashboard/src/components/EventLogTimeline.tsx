import type { AuditLogEntry } from "@icarus-tether/types";

interface EventLogTimelineProps {
  logs: AuditLogEntry[];
}

export default function EventLogTimeline({ logs }: EventLogTimelineProps) {
  return (
    <section>
      <h2>감사 로그</h2>
      <ul>
        {logs.map((log) => (
          <li key={log.id}>
            [{log.timestamp}] {log.toolName} → {log.decision}
          </li>
        ))}
      </ul>
    </section>
  );
}