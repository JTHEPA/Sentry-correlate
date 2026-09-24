package com.jojo.sentrycorrelate.correlation;

import com.jojo.sentrycorrelate.geo.GeoIpLookup;
import com.jojo.sentrycorrelate.model.Alert;
import com.jojo.sentrycorrelate.model.EventType;
import com.jojo.sentrycorrelate.model.SecurityEvent;
import com.jojo.sentrycorrelate.model.Severity;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Detects "impossible travel": the same username successfully logging in
 * from two different countries within a window too short for a real
 * person to have travelled between them. A classic indicator of a shared
 * or stolen credential being used from two places at once.
 *
 * Unlike the other rules, this one needs state beyond a single IP's
 * window (a username's last known login location), so it keeps its own
 * small internal map rather than relying solely on {@link EventWindowStore}.
 */
public final class GeoAnomalyRule implements CorrelationRule {

    private record LastLogin(String ip, String country, Instant at) {}

    private final GeoIpLookup geoIpLookup;
    private final Duration impossibleTravelWindow;
    private final Map<String, LastLogin> lastLoginByUser = new ConcurrentHashMap<>();

    public GeoAnomalyRule(GeoIpLookup geoIpLookup, Duration impossibleTravelWindow) {
        this.geoIpLookup = geoIpLookup;
        this.impossibleTravelWindow = impossibleTravelWindow;
    }

    @Override
    public String name() {
        return "impossible-travel";
    }

    @Override
    public Optional<Alert> evaluate(SecurityEvent event, EventWindowStore store) {
        if (event.type() != EventType.AUTH_SUCCESS || event.username() == null) {
            return Optional.empty();
        }

        Optional<String> country = geoIpLookup.countryFor(event.sourceIp());
        if (country.isEmpty()) {
            return Optional.empty();
        }

        LastLogin previous = lastLoginByUser.put(event.username(),
                new LastLogin(event.sourceIp(), country.get(), event.timestamp()));

        if (previous == null || previous.country().equals(country.get())) {
            return Optional.empty();
        }

        Duration gap = Duration.between(previous.at(), event.timestamp());
        if (gap.isNegative() || gap.compareTo(impossibleTravelWindow) > 0) {
            return Optional.empty(); // enough time may plausibly have passed
        }

        String summary = "User '%s' logged in from %s (%s) then from %s (%s) only %ds later — impossible travel"
                .formatted(event.username(), previous.ip(), previous.country(),
                        event.sourceIp(), country.get(), gap.toSeconds());

        return Optional.of(new Alert(name(), Severity.CRITICAL, event.sourceIp(), summary,
                "T1078.004 (Valid Accounts: Cloud Accounts)", List.of(event.id())));
    }
}
