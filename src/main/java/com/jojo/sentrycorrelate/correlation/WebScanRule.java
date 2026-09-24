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
 * Detects two distinct web-layer attack signatures:
 *
 * 1. Reconnaissance scanning — {@code notFoundThreshold} or more
 *    HTTP_NOT_FOUND responses to the same IP within {@code window}
 *    (someone probing for /admin.php, /.env, /phpmyadmin, etc.).
 * 2. Any HTTP_SUSPICIOUS request — a single request matching a known
 *    attack-payload pattern (SQLi, path traversal, XSS probe) is
 *    significant on its own and is alerted immediately, not batched.
 */
public final class WebScanRule implements CorrelationRule {

    private final int notFoundThreshold;
    private final Duration window;

    public WebScanRule(int notFoundThreshold, Duration window) {
        this.notFoundThreshold = notFoundThreshold;
        this.window = window;
    }

    @Override
    public String name() {
        return "web-recon-scan";
    }

    @Override
    public Optional<Alert> evaluate(SecurityEvent event, EventWindowStore store) {
        if (event.type() == EventType.HTTP_SUSPICIOUS) {
            String summary = "Suspicious payload in request from %s: %s".formatted(event.sourceIp(), event.path());
            return Optional.of(new Alert("suspicious-payload", Severity.HIGH, event.sourceIp(), summary,
                    "T1190 (Exploit Public-Facing Application)", List.of(event.id())));
        }

        if (event.type() != EventType.HTTP_NOT_FOUND) {
            return Optional.empty();
        }

        List<SecurityEvent> notFounds = store.recentFor(event.sourceIp(), window, event.timestamp(),
                e -> e.type() == EventType.HTTP_NOT_FOUND);

        if (notFounds.size() < notFoundThreshold) {
            return Optional.empty();
        }

        String summary = "%d distinct not-found requests from %s within %ds — likely endpoint enumeration: %s".formatted(
                notFounds.size(), event.sourceIp(), window.toSeconds(),
                notFounds.stream().map(SecurityEvent::path).distinct().collect(Collectors.joining(", ")));

        return Optional.of(new Alert(name(), Severity.MEDIUM, event.sourceIp(), summary,
                "T1595 (Active Scanning)", notFounds.stream().map(SecurityEvent::id).toList()));
    }
}
