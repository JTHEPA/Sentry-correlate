package com.jojo.sentrycorrelate.alerting;

import com.jojo.sentrycorrelate.model.Alert;
import com.jojo.sentrycorrelate.util.SimpleLogger;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Fans a raised alert out to every registered {@link AlertChannel}, and
 * records it in the {@link AlertStore} for the REST API to query.
 *
 * Real correlation rules will re-fire on every subsequent matching event
 * (a brute-force burst that keeps going re-triggers {@code BruteForceRule}
 * on every new failure past the threshold) — without suppression this
 * floods every channel with near-duplicate alerts ("alert fatigue" is a
 * real, well-known SOC problem). This dispatcher suppresses repeats of the
 * same rule+source-IP combination within {@code suppressionWindow}.
 */
public final class AlertDispatcher implements Consumer<Alert> {

    private static final SimpleLogger log = SimpleLogger.of(AlertDispatcher.class);

    private final List<AlertChannel> channels;
    private final AlertStore store;
    private final Duration suppressionWindow;
    private final Map<String, Instant> lastDispatchedAt = new ConcurrentHashMap<>();

    public AlertDispatcher(List<AlertChannel> channels, AlertStore store, Duration suppressionWindow) {
        this.channels = List.copyOf(channels);
        this.store = store;
        this.suppressionWindow = suppressionWindow;
    }

    @Override
    public void accept(Alert alert) {
        Instant now = Instant.now();
        Instant last = lastDispatchedAt.get(alert.dedupeKey());

        if (last != null && Duration.between(last, now).compareTo(suppressionWindow) < 0) {
            log.info("Suppressed duplicate alert (" + alert.dedupeKey() + ") within suppression window");
            return;
        }

        lastDispatchedAt.put(alert.dedupeKey(), now);
        store.save(alert);

        for (AlertChannel channel : channels) {
            try {
                channel.send(alert);
            } catch (Exception e) {
                // One channel failing (e.g. webhook down) must never stop
                // the alert from reaching the others.
                log.error("Channel '" + channel.channelName() + "' failed to deliver alert " + alert.id(), e);
            }
        }
    }
}
