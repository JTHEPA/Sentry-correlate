package com.jojo.sentrycorrelate;

import com.jojo.sentrycorrelate.correlation.EventWindowStore;
import com.jojo.sentrycorrelate.model.EventType;
import com.jojo.sentrycorrelate.model.SecurityEvent;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

public class EventWindowStoreTest {

    private SecurityEvent authFailure(Instant at, String ip) {
        return new SecurityEvent(at, "ssh", EventType.AUTH_FAILURE, ip, "admin", null, "raw");
    }

    public void testRecentForReturnsEventsWithinWindow() {
        EventWindowStore store = new EventWindowStore(Duration.ofMinutes(30));
        Instant base = Instant.parse("2026-01-01T00:00:00Z");

        store.record(authFailure(base, "1.2.3.4"));
        store.record(authFailure(base.plusSeconds(10), "1.2.3.4"));
        store.record(authFailure(base.plusSeconds(200), "1.2.3.4")); // outside a 60s window from base+10

        List<SecurityEvent> recent = store.recentFor("1.2.3.4", Duration.ofSeconds(60), base.plusSeconds(15));
        Assert.equals(2, recent.size(), "Should only include events within the 60s window");
    }

    public void testRecentForDifferentIpsAreIsolated() {
        EventWindowStore store = new EventWindowStore(Duration.ofMinutes(30));
        Instant base = Instant.parse("2026-01-01T00:00:00Z");

        store.record(authFailure(base, "1.2.3.4"));
        store.record(authFailure(base, "5.6.7.8"));

        Assert.equals(1, store.recentFor("1.2.3.4", Duration.ofMinutes(5), base).size(),
                "Events for one IP should not leak into another IP's window");
    }

    public void testUnknownIpReturnsEmptyList() {
        EventWindowStore store = new EventWindowStore(Duration.ofMinutes(30));
        Assert.equals(0, store.recentFor("9.9.9.9", Duration.ofMinutes(5), Instant.now()).size(),
                "Unknown IP should return an empty list, not throw");
    }

    public void testOldEventsArePrunedBeyondMaxRetention() {
        EventWindowStore store = new EventWindowStore(Duration.ofSeconds(30));
        Instant base = Instant.parse("2026-01-01T00:00:00Z");

        store.record(authFailure(base, "1.2.3.4"));
        // This insert is >30s after the first, so the first should be pruned on insert.
        store.record(authFailure(base.plusSeconds(40), "1.2.3.4"));

        List<SecurityEvent> all = store.recentFor("1.2.3.4", Duration.ofMinutes(10), base.plusSeconds(40));
        Assert.equals(1, all.size(), "Event older than max retention should have been pruned");
    }
}
