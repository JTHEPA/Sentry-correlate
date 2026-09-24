package com.jojo.sentrycorrelate.alerting;

import com.jojo.sentrycorrelate.model.Alert;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** Keeps every raised (non-suppressed) alert queryable via the REST API. */
public final class AlertStore {

    private final Map<String, Alert> alerts = new ConcurrentHashMap<>();

    public void save(Alert alert) {
        alerts.put(alert.id(), alert);
    }

    public Optional<Alert> findById(String id) {
        return Optional.ofNullable(alerts.get(id));
    }

    /** Most recent first. */
    public List<Alert> findAll() {
        return alerts.values().stream()
                .sorted(Comparator.comparing(Alert::triggeredAt).reversed())
                .toList();
    }

    public int count() {
        return alerts.size();
    }
}
