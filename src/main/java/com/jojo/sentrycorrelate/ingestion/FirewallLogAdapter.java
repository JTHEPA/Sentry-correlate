package com.jojo.sentrycorrelate.ingestion;

import com.jojo.sentrycorrelate.model.EventType;
import com.jojo.sentrycorrelate.model.SecurityEvent;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses a simplified firewall log line, e.g.:
 *   2026-09-21T09:20:00 firewall BLOCK 192.0.2.44 -> 10.0.0.5:3389
 *
 * Firewall events mostly serve as corroborating evidence in this system —
 * a source IP already flagged by SSH/web rules that also shows up
 * hammering blocked ports strengthens the case that it's hostile, which is
 * exactly the kind of cross-source correlation a SIEM is for.
 */
public final class FirewallLogAdapter implements LogSource {

    private static final Pattern LINE = Pattern.compile(
            "^(\\S+) firewall (BLOCK|ALLOW) (\\S+) -> \\S+:(\\d+)$");

    @Override
    public String sourceSystem() {
        return "firewall";
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
        EventType type = "BLOCK".equals(m.group(2)) ? EventType.FIREWALL_BLOCK : EventType.FIREWALL_ALLOW;
        String sourceIp = m.group(3);

        return Optional.of(new SecurityEvent(timestamp, sourceSystem(), type, sourceIp, null, null, rawLine));
    }
}
