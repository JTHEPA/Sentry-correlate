package com.jojo.sentrycorrelate;

import com.jojo.sentrycorrelate.correlation.CompromiseAfterBruteForceRule;
import com.jojo.sentrycorrelate.correlation.EventWindowStore;
import com.jojo.sentrycorrelate.model.Alert;
import com.jojo.sentrycorrelate.model.EventType;
import com.jojo.sentrycorrelate.model.SecurityEvent;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

public class CompromiseAfterBruteForceRuleTest {

    public void testSuccessAfterEnoughFailuresRaisesCriticalAlert() {
        CompromiseAfterBruteForceRule rule = new CompromiseAfterBruteForceRule(3, Duration.ofSeconds(60));
        EventWindowStore store = new EventWindowStore(Duration.ofMinutes(10));
        Instant base = Instant.parse("2026-01-01T00:00:00Z");

        for (int i = 0; i < 3; i++) {
            SecurityEvent f = new SecurityEvent(base.plusSeconds(i), "ssh", EventType.AUTH_FAILURE,
                    "1.2.3.4", "admin", null, "raw");
            store.record(f);
            rule.evaluate(f, store);
        }

        SecurityEvent success = new SecurityEvent(base.plusSeconds(10), "ssh", EventType.AUTH_SUCCESS,
                "1.2.3.4", "admin", null, "raw");
        store.record(success);
        Optional<Alert> alert = rule.evaluate(success, store);

        Assert.isTrue(alert.isPresent(), "Success right after 3 failures should trigger the compromise rule");
        Assert.equals("T1078 (Valid Accounts)", alert.get().mitreTechnique(), "Should carry the T1078 technique tag");
    }

    public void testSuccessWithoutPriorFailuresDoesNotAlert() {
        CompromiseAfterBruteForceRule rule = new CompromiseAfterBruteForceRule(3, Duration.ofSeconds(60));
        EventWindowStore store = new EventWindowStore(Duration.ofMinutes(10));

        SecurityEvent success = new SecurityEvent(Instant.now(), "ssh", EventType.AUTH_SUCCESS,
                "1.2.3.4", "admin", null, "raw");
        store.record(success);

        Assert.isTrue(rule.evaluate(success, store).isEmpty(), "A clean login with no prior failures should not alert");
    }
}
