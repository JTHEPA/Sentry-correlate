package com.jojo.sentrycorrelate;

import com.jojo.sentrycorrelate.correlation.BruteForceRule;
import com.jojo.sentrycorrelate.correlation.EventWindowStore;
import com.jojo.sentrycorrelate.model.Alert;
import com.jojo.sentrycorrelate.model.EventType;
import com.jojo.sentrycorrelate.model.SecurityEvent;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

public class BruteForceRuleTest {

    private SecurityEvent failure(Instant at, String ip) {
        return new SecurityEvent(at, "ssh", EventType.AUTH_FAILURE, ip, "admin", null, "raw");
    }

    public void testNoAlertBelowThreshold() {
        BruteForceRule rule = new BruteForceRule(5, Duration.ofSeconds(60));
        EventWindowStore store = new EventWindowStore(Duration.ofMinutes(10));
        Instant base = Instant.parse("2026-01-01T00:00:00Z");

        Optional<Alert> alert = Optional.empty();
        for (int i = 0; i < 3; i++) {
            SecurityEvent e = failure(base.plusSeconds(i), "1.2.3.4");
            store.record(e);
            alert = rule.evaluate(e, store);
        }

        Assert.isTrue(alert.isEmpty(), "3 failures should not trip a threshold-5 brute-force rule");
    }

    public void testAlertsAtThreshold() {
        BruteForceRule rule = new BruteForceRule(5, Duration.ofSeconds(60));
        EventWindowStore store = new EventWindowStore(Duration.ofMinutes(10));
        Instant base = Instant.parse("2026-01-01T00:00:00Z");

        Optional<Alert> alert = Optional.empty();
        for (int i = 0; i < 5; i++) {
            SecurityEvent e = failure(base.plusSeconds(i), "1.2.3.4");
            store.record(e);
            alert = rule.evaluate(e, store);
        }

        Assert.isTrue(alert.isPresent(), "5th failure within the window should trip the rule");
        Assert.equals("brute-force-auth", alert.get().ruleName(), "Rule name should match");
        Assert.equals("T1110 (Brute Force)", alert.get().mitreTechnique(), "Should be tagged with the MITRE T1110 technique");
    }

    public void testFailuresOutsideWindowDoNotCount() {
        BruteForceRule rule = new BruteForceRule(3, Duration.ofSeconds(30));
        EventWindowStore store = new EventWindowStore(Duration.ofMinutes(10));
        Instant base = Instant.parse("2026-01-01T00:00:00Z");

        store.record(failure(base, "1.2.3.4"));
        store.record(failure(base.plusSeconds(5), "1.2.3.4"));
        // Big gap — outside the 30s window relative to the 3rd event below.
        SecurityEvent third = failure(base.plusSeconds(100), "1.2.3.4");
        store.record(third);
        Optional<Alert> alert = rule.evaluate(third, store);

        Assert.isTrue(alert.isEmpty(), "Old failures outside the window should not count toward the threshold");
    }

    public void testIgnoresNonAuthFailureEvents() {
        BruteForceRule rule = new BruteForceRule(1, Duration.ofSeconds(60));
        EventWindowStore store = new EventWindowStore(Duration.ofMinutes(10));
        SecurityEvent success = new SecurityEvent(Instant.now(), "ssh", EventType.AUTH_SUCCESS,
                "1.2.3.4", "admin", null, "raw");
        store.record(success);

        Assert.isTrue(rule.evaluate(success, store).isEmpty(), "AUTH_SUCCESS should never trigger the brute-force rule");
    }
}
