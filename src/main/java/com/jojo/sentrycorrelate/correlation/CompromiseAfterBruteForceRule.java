package com.jojo.sentrycorrelate.correlation;

import com.jojo.sentrycorrelate.model.Alert;
import com.jojo.sentrycorrelate.model.EventType;
import com.jojo.sentrycorrelate.model.SecurityEvent;
import com.jojo.sentrycorrelate.model.Severity;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * The highest-value correlation in the system: a successful login from an
 * IP that was just failing repeatedly. Neither the failures alone nor the
 * single success alone tell you much — a burst of failures could be a
 * forgotten password, and one success is normal traffic. Together, in a
 * short window, they strongly suggest the password guessing worked.
 */
public final class CompromiseAfterBruteForceRule implements CorrelationRule {

    private final int failureThreshold;
    private final Duration window;

    public CompromiseAfterBruteForceRule(int failureThreshold, Duration window) {
        this.failureThreshold = failureThreshold;
        this.window = window;
    }

    @Override
    public String name() {
        return "compromise-after-brute-force";
    }

    @Override
    public Optional<Alert> evaluate(SecurityEvent event, EventWindowStore store) {
        if (event.type() != EventType.AUTH_SUCCESS) {
            return Optional.empty();
        }

        List<SecurityEvent> priorFailures = store.recentFor(event.sourceIp(), window, event.timestamp(),
                e -> e.type() == EventType.AUTH_FAILURE && !e.id().equals(event.id()));

        if (priorFailures.size() < failureThreshold) {
            return Optional.empty();
        }

        String summary = "Successful login for '%s' from %s followed %d failed attempts within %ds — credentials likely compromised"
                .formatted(event.username(), event.sourceIp(), priorFailures.size(), window.toSeconds());

        List<String> evidence = new java.util.ArrayList<>(priorFailures.stream().map(SecurityEvent::id).toList());
        evidence.add(event.id());

        return Optional.of(new Alert(name(), Severity.CRITICAL, event.sourceIp(), summary,
                "T1078 (Valid Accounts)", evidence));
    }
}
