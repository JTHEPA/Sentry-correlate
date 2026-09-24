package com.jojo.sentrycorrelate.correlation;

import com.jojo.sentrycorrelate.model.Alert;
import com.jojo.sentrycorrelate.model.EventType;
import com.jojo.sentrycorrelate.model.SecurityEvent;
import com.jojo.sentrycorrelate.model.Severity;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Detects password-guessing: {@code threshold} or more AUTH_FAILURE events
 * from the same source IP within {@code window}. This is the classic
 * "single event is noise, a burst is a signal" correlation case — one
 * failed SSH login means nothing, five in ten seconds means someone is
 * guessing passwords.
 */
public final class BruteForceRule implements CorrelationRule {

    private final int threshold;
    private final Duration window;

    public BruteForceRule(int threshold, Duration window) {
        this.threshold = threshold;
        this.window = window;
    }

    @Override
    public String name() {
        return "brute-force-auth";
    }

    @Override
    public Optional<Alert> evaluate(SecurityEvent event, EventWindowStore store) {
        if (event.type() != EventType.AUTH_FAILURE) {
            return Optional.empty();
        }

        List<SecurityEvent> failures = store.recentFor(event.sourceIp(), window, event.timestamp(),
                e -> e.type() == EventType.AUTH_FAILURE);

        if (failures.size() < threshold) {
            return Optional.empty();
        }

        String summary = "%d failed authentication attempts from %s within %ds (user(s): %s)".formatted(
                failures.size(), event.sourceIp(), window.toSeconds(),
                failures.stream().map(SecurityEvent::username).distinct().collect(Collectors.joining(", ")));

        return Optional.of(new Alert(name(), Severity.HIGH, event.sourceIp(), summary, "T1110 (Brute Force)",
                failures.stream().map(SecurityEvent::id).toList()));
    }
}
