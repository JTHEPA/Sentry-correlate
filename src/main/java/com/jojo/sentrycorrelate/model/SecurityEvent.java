package com.jojo.sentrycorrelate.model;

import java.time.Instant;
import java.util.UUID;

/**
 * The common representation every log source is normalized into. This is
 * the contract that lets the correlation engine reason about "an SSH
 * failure" and "a suspicious web request" the same way, without knowing
 * anything about auth.log or an access-log line format.
 */
public final class SecurityEvent {

    private final String id;
    private final Instant timestamp;
    private final String sourceSystem; // "ssh", "web", "firewall"
    private final EventType type;
    private final String sourceIp;
    private final String username;     // nullable — only auth events have one
    private final String path;         // nullable — only web events have one
    private final String rawLine;

    public SecurityEvent(Instant timestamp, String sourceSystem, EventType type,
                          String sourceIp, String username, String path, String rawLine) {
        this.id = UUID.randomUUID().toString();
        this.timestamp = timestamp;
        this.sourceSystem = sourceSystem;
        this.type = type;
        this.sourceIp = sourceIp;
        this.username = username;
        this.path = path;
        this.rawLine = rawLine;
    }

    public String id() { return id; }
    public Instant timestamp() { return timestamp; }
    public String sourceSystem() { return sourceSystem; }
    public EventType type() { return type; }
    public String sourceIp() { return sourceIp; }
    public String username() { return username; }
    public String path() { return path; }
    public String rawLine() { return rawLine; }

    @Override
    public String toString() {
        return "SecurityEvent{%s %s ip=%s user=%s path=%s}"
                .formatted(sourceSystem, type, sourceIp, username, path);
    }
}
