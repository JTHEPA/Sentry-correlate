package com.jojo.sentrycorrelate.ingestion;

import com.jojo.sentrycorrelate.model.EventType;
import com.jojo.sentrycorrelate.model.SecurityEvent;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses a simplified SSH auth-log line, e.g.:
 *   2026-09-21T09:10:00 sshd Failed password for admin from 203.0.113.5 port 51410
 *   2026-09-21T09:10:30 sshd Accepted password for admin from 203.0.113.5 port 51420
 *
 * This mirrors the shape of a real /var/log/auth.log SSH line closely
 * enough to demonstrate the parsing/normalization problem without pulling
 * in a full syslog parser.
 */
public final class SshAuthLogAdapter implements LogSource {

    private static final Pattern LINE = Pattern.compile(
            "^(\\S+) sshd (Failed|Accepted) password for (\\S+) from (\\S+) port (\\d+)$");

    @Override
    public String sourceSystem() {
        return "ssh";
    }

    @Override
    public Optional<SecurityEvent> parse(String rawLine) {
        if (rawLine == null || rawLine.isBlank()) {
            return Optional.empty();
        }
        Matcher m = LINE.matcher(rawLine.trim());
        if (!m.matches()) {
            return Optional.empty();
        }

        Instant timestamp = LocalDateTime.parse(m.group(1))
                .atZone(java.time.ZoneOffset.UTC).toInstant();
        EventType type = "Failed".equals(m.group(2)) ? EventType.AUTH_FAILURE : EventType.AUTH_SUCCESS;
        String username = m.group(3);
        String sourceIp = m.group(4);

        return Optional.of(new SecurityEvent(timestamp, sourceSystem(), type, sourceIp, username, null, rawLine));
    }
}
