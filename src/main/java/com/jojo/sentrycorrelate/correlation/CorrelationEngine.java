package com.jojo.sentrycorrelate.correlation;

import com.jojo.sentrycorrelate.event.Event;
import com.jojo.sentrycorrelate.event.EventBus;
import com.jojo.sentrycorrelate.model.Alert;
import com.jojo.sentrycorrelate.model.SecurityEvent;
import com.jojo.sentrycorrelate.util.SimpleLogger;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * The integration point of the whole system: every normalized
 * {@link SecurityEvent}, regardless of which log source it came from,
 * flows through here. The engine records the event, runs every registered
 * {@link CorrelationRule} against it, and hands any resulting
 * {@link Alert} off to a dispatcher — then publishes an ALERT_RAISED
 * event on the bus so other parts of the system (an audit trail today, a
 * ticketing integration tomorrow) can react without the engine knowing
 * about them.
 */
public final class CorrelationEngine {

    private static final SimpleLogger log = SimpleLogger.of(CorrelationEngine.class);

    private final EventWindowStore store;
    private final List<CorrelationRule> rules;
    private final Consumer<Alert> alertDispatcher;
    private final EventBus eventBus;

    private final Map<String, AtomicLong> eventsBySource = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> alertsByRule = new ConcurrentHashMap<>();

    public CorrelationEngine(EventWindowStore store, List<CorrelationRule> rules,
                              Consumer<Alert> alertDispatcher, EventBus eventBus) {
        this.store = store;
        this.rules = List.copyOf(rules);
        this.alertDispatcher = alertDispatcher;
        this.eventBus = eventBus;
    }

    public void process(SecurityEvent event) {
        store.record(event);
        eventsBySource.computeIfAbsent(event.sourceSystem(), k -> new AtomicLong()).incrementAndGet();

        for (CorrelationRule rule : rules) {
            rule.evaluate(event, store).ifPresent(alert -> {
                alertsByRule.computeIfAbsent(alert.ruleName(), k -> new AtomicLong()).incrementAndGet();
                alertDispatcher.accept(alert);
                eventBus.publish(new Event("ALERT_RAISED", Map.of(
                        "alertId", alert.id(), "ruleName", alert.ruleName(), "sourceIp", alert.sourceIp())));
            });
        }
    }

    public Map<String, Long> eventsBySource() {
        Map<String, Long> snapshot = new ConcurrentHashMap<>();
        eventsBySource.forEach((k, v) -> snapshot.put(k, v.get()));
        return snapshot;
    }

    public Map<String, Long> alertsByRule() {
        Map<String, Long> snapshot = new ConcurrentHashMap<>();
        alertsByRule.forEach((k, v) -> snapshot.put(k, v.get()));
        return snapshot;
    }
}
