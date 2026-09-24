package com.jojo.sentrycorrelate.event;

import java.time.Instant;
import java.util.Map;

/**
 * A system-internal event (distinct from {@code SecurityEvent}, which is a
 * parsed log entry). Used to decouple the correlation engine from whatever
 * wants to react to an alert being raised (audit log, future integrations
 * like a ticketing system).
 */
public final class Event {

    private final String type;
    private final Instant occurredAt;
    private final Map<String, Object> payload;

    public Event(String type, Map<String, Object> payload) {
        this.type = type;
        this.payload = Map.copyOf(payload);
        this.occurredAt = Instant.now();
    }

    public String type() {
        return type;
    }

    public Instant occurredAt() {
        return occurredAt;
    }

    public Object get(String key) {
        return payload.get(key);
    }

    @Override
    public String toString() {
        return "Event{type='%s', occurredAt=%s, payload=%s}".formatted(type, occurredAt, payload);
    }
}
