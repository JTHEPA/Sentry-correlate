package com.jojo.sentrycorrelate;

import com.jojo.sentrycorrelate.alerting.AlertChannel;
import com.jojo.sentrycorrelate.alerting.AlertDispatcher;
import com.jojo.sentrycorrelate.alerting.AlertStore;
import com.jojo.sentrycorrelate.model.Alert;
import com.jojo.sentrycorrelate.model.Severity;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public class AlertDispatcherTest {

    private AlertChannel countingChannel(AtomicInteger counter) {
        return new AlertChannel() {
            @Override public void send(Alert alert) { counter.incrementAndGet(); }
            @Override public String channelName() { return "counting"; }
        };
    }

    public void testFirstAlertIsDispatchedAndStored() {
        AtomicInteger deliveries = new AtomicInteger(0);
        AlertStore store = new AlertStore();
        AlertDispatcher dispatcher = new AlertDispatcher(List.of(countingChannel(deliveries)), store, Duration.ofMinutes(5));

        Alert alert = new Alert("brute-force-auth", Severity.HIGH, "1.2.3.4", "test", "T1110 (Brute Force)", List.of());
        dispatcher.accept(alert);

        Assert.equals(1, deliveries.get(), "First alert should reach the channel");
        Assert.equals(1, store.count(), "First alert should be recorded in the store");
    }

    public void testDuplicateWithinWindowIsSuppressed() {
        AtomicInteger deliveries = new AtomicInteger(0);
        AlertStore store = new AlertStore();
        AlertDispatcher dispatcher = new AlertDispatcher(List.of(countingChannel(deliveries)), store, Duration.ofMinutes(5));

        Alert first = new Alert("brute-force-auth", Severity.HIGH, "1.2.3.4", "test1", "T1110 (Brute Force)", List.of());
        Alert repeat = new Alert("brute-force-auth", Severity.HIGH, "1.2.3.4", "test2", "T1110 (Brute Force)", List.of());
        dispatcher.accept(first);
        dispatcher.accept(repeat);

        Assert.equals(1, deliveries.get(), "Second alert with the same rule+IP should be suppressed within the window");
        Assert.equals(1, store.count(), "Suppressed alert should not be stored either");
    }

    public void testDifferentSourceIpIsNotSuppressed() {
        AtomicInteger deliveries = new AtomicInteger(0);
        AlertStore store = new AlertStore();
        AlertDispatcher dispatcher = new AlertDispatcher(List.of(countingChannel(deliveries)), store, Duration.ofMinutes(5));

        dispatcher.accept(new Alert("brute-force-auth", Severity.HIGH, "1.2.3.4", "a", "T1110 (Brute Force)", List.of()));
        dispatcher.accept(new Alert("brute-force-auth", Severity.HIGH, "5.6.7.8", "b", "T1110 (Brute Force)", List.of()));

        Assert.equals(2, deliveries.get(), "Same rule but a different source IP is a different attacker — should not be suppressed");
    }

    public void testOneFailingChannelDoesNotBlockOthers() {
        AtomicInteger workingChannelDeliveries = new AtomicInteger(0);
        AlertChannel broken = new AlertChannel() {
            @Override public void send(Alert alert) { throw new RuntimeException("channel down"); }
            @Override public String channelName() { return "broken"; }
        };
        AlertStore store = new AlertStore();
        AlertDispatcher dispatcher = new AlertDispatcher(
                List.of(broken, countingChannel(workingChannelDeliveries)), store, Duration.ofMinutes(5));

        dispatcher.accept(new Alert("brute-force-auth", Severity.HIGH, "1.2.3.4", "a", "T1110 (Brute Force)", List.of()));

        Assert.equals(1, workingChannelDeliveries.get(), "A broken channel must not prevent delivery to a working one");
    }
}
