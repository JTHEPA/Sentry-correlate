package com.jojo.sentrycorrelate.ingestion;

import com.jojo.sentrycorrelate.model.EventType;
import com.jojo.sentrycorrelate.model.SecurityEvent;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses a simplified web-server access-log line, e.g.:
 *   2026-09-21T09:14:20 192.0.2.44 GET /wp-login.php 404
 *   2026-09-21T09:15:00 192.0.2.44 GET /products?id=1' OR '1'='1 200
 *
 * Classifies each request as a plain HTTP_REQUEST, an HTTP_NOT_FOUND (used
 * by {@code WebScanRule} to detect directory/endpoint enumeration), or
 * HTTP_SUSPICIOUS when the path matches a known attack-payload pattern
 * (SQL injection, path traversal, XSS probe) regardless of the response
 * code — a single suspicious request is worth flagging immediately.
 */
public final class WebAccessLogAdapter implements LogSource {

    private static final Pattern LINE = Pattern.compile(
            "^(\\S+) (\\S+) (GET|POST|PUT|DELETE) (\\S.*\\S|\\S) (\\d{3})$");

    private static final Pattern SUSPICIOUS_PAYLOAD = Pattern.compile(
            "(?i)(union\\s+select|or\\s+'?1'?=?'?1|\\.\\./|<script|drop\\s+table)");

    @Override
    public String sourceSystem() {
        return "web";
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
        String sourceIp = m.group(2);
        String path = m.group(4);
        int status = Integer.parseInt(m.group(5));

        EventType type;
        if (SUSPICIOUS_PAYLOAD.matcher(path).find()) {
            type = EventType.HTTP_SUSPICIOUS;
        } else if (status == 404) {
            type = EventType.HTTP_NOT_FOUND;
        } else {
            type = EventType.HTTP_REQUEST;
        }

        return Optional.of(new SecurityEvent(timestamp, sourceSystem(), type, sourceIp, null, path, rawLine));
    }
}
