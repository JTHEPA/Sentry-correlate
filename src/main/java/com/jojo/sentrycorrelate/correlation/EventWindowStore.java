package com.jojo.sentrycorrelate.correlation;

import com.jojo.sentrycorrelate.model.SecurityEvent;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Keeps recent {@link SecurityEvent}s per source IP so rules can ask
 * "how many auth failures has this IP had in the last 2 minutes?" without
 * every rule re-implementing its own windowing.
 *
 * Retention is bounded by {@code maxRetention} — old events are pruned on
 * every insert so memory doesn't grow unbounded on a long-running process
 * (a real deployment would back this with a time-series store; this is
 * the same interface a Redis-backed implementation would expose).
 */
public final class EventWindowStore {

    private final Duration maxRetention;
    private final Map<String, Deque<SecurityEvent>> byIp = new ConcurrentHashMap<>();

    public EventWindowStore(Duration maxRetention) {
        this.maxRetention = maxRetention;
    }

    public synchronized void record(SecurityEvent event) {
        Deque<SecurityEvent> deque = byIp.computeIfAbsent(event.sourceIp(), k -> new ArrayDeque<>());
        deque.addLast(event);
        prune(deque, event.timestamp());
    }

    /** All events for {@code ip} within {@code window} before {@code now}, oldest first. */
    public synchronized List<SecurityEvent> recentFor(String ip, Duration window, Instant now) {
        Deque<SecurityEvent> deque = byIp.get(ip);
        if (deque == null) {
            return List.of();
        }
        Instant cutoff = now.minus(window);
        return deque.stream()
                .filter(e -> !e.timestamp().isBefore(cutoff) && !e.timestamp().isAfter(now))
                .collect(Collectors.toList());
    }

    /** Convenience overload with an extra type/content filter. */
    public synchronized List<SecurityEvent> recentFor(String ip, Duration window, Instant now,
                                                        Predicate<SecurityEvent> filter) {
        return recentFor(ip, window, now).stream().filter(filter).collect(Collectors.toList());
    }

    private void prune(Deque<SecurityEvent> deque, Instant now) {
        Instant cutoff = now.minus(maxRetention);
        while (!deque.isEmpty() && deque.peekFirst().timestamp().isBefore(cutoff)) {
            deque.pollFirst();
        }
    }
}
