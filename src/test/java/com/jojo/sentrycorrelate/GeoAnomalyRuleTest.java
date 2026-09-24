package com.jojo.sentrycorrelate;

import com.jojo.sentrycorrelate.correlation.EventWindowStore;
import com.jojo.sentrycorrelate.correlation.GeoAnomalyRule;
import com.jojo.sentrycorrelate.geo.GeoIpLookup;
import com.jojo.sentrycorrelate.model.Alert;
import com.jojo.sentrycorrelate.model.EventType;
import com.jojo.sentrycorrelate.model.SecurityEvent;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

public class GeoAnomalyRuleTest {

    private SecurityEvent success(Instant at, String user, String ip) {
        return new SecurityEvent(at, "ssh", EventType.AUTH_SUCCESS, ip, user, null, "raw");
    }

    public void testDifferentCountryWithinWindowAlerts() {
        GeoAnomalyRule rule = new GeoAnomalyRule(new GeoIpLookup(), Duration.ofMinutes(10));
        EventWindowStore store = new EventWindowStore(Duration.ofMinutes(30));
        Instant base = Instant.parse("2026-01-01T00:00:00Z");

        SecurityEvent first = success(base, "admin", "203.0.113.5"); // South Africa
        store.record(first);
        rule.evaluate(first, store);

        SecurityEvent second = success(base.plusSeconds(90), "admin", "198.51.100.99"); // Russia
        store.record(second);
        Optional<Alert> alert = rule.evaluate(second, store);

        Assert.isTrue(alert.isPresent(), "Login from a new country 90s later should be flagged as impossible travel");
        Assert.equals("impossible-travel", alert.get().ruleName(), "Rule name should be impossible-travel");
        Assert.equals("T1078.004 (Valid Accounts: Cloud Accounts)", alert.get().mitreTechnique(), "Should carry T1078.004");
    }

    public void testSameCountryDoesNotAlert() {
        GeoAnomalyRule rule = new GeoAnomalyRule(new GeoIpLookup(), Duration.ofMinutes(10));
        EventWindowStore store = new EventWindowStore(Duration.ofMinutes(30));
        Instant base = Instant.parse("2026-01-01T00:00:00Z");

        SecurityEvent first = success(base, "admin", "203.0.113.5");
        store.record(first);
        rule.evaluate(first, store);

        SecurityEvent second = success(base.plusSeconds(30), "admin", "203.0.113.9"); // same network/country
        store.record(second);

        Assert.isTrue(rule.evaluate(second, store).isEmpty(), "Repeated logins from the same country should not alert");
    }

    public void testDifferentCountryOutsideWindowDoesNotAlert() {
        GeoAnomalyRule rule = new GeoAnomalyRule(new GeoIpLookup(), Duration.ofMinutes(10));
        EventWindowStore store = new EventWindowStore(Duration.ofHours(2));
        Instant base = Instant.parse("2026-01-01T00:00:00Z");

        SecurityEvent first = success(base, "admin", "203.0.113.5");
        store.record(first);
        rule.evaluate(first, store);

        // An hour later is plenty of time to have actually travelled.
        SecurityEvent second = success(base.plus(Duration.ofHours(1)), "admin", "198.51.100.99");
        store.record(second);

        Assert.isTrue(rule.evaluate(second, store).isEmpty(),
                "A country change with enough elapsed time should not be flagged as impossible travel");
    }

    public void testFirstLoginEverDoesNotAlert() {
        GeoAnomalyRule rule = new GeoAnomalyRule(new GeoIpLookup(), Duration.ofMinutes(10));
        EventWindowStore store = new EventWindowStore(Duration.ofMinutes(30));

        SecurityEvent first = success(Instant.now(), "brandnewuser", "203.0.113.5");
        store.record(first);

        Assert.isTrue(rule.evaluate(first, store).isEmpty(), "There's no 'previous' location to compare against yet");
    }
}
