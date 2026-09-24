package com.jojo.sentrycorrelate.event;

import com.jojo.sentrycorrelate.util.SimpleLogger;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * In-memory publish/subscribe bus. Lets the correlation engine announce
 * "an alert was raised" without knowing who — an audit logger today, a
 * ticketing-system integration tomorrow — is listening.
 */
public final class EventBus {

    private static final SimpleLogger log = SimpleLogger.of(EventBus.class);

    private final Map<String, List<EventListener>> listeners = new ConcurrentHashMap<>();

    public void subscribe(String eventType, EventListener listener) {
        listeners.computeIfAbsent(eventType, k -> new CopyOnWriteArrayList<>()).add(listener);
    }

    public void publish(Event event) {
        List<EventListener> subscribers = listeners.getOrDefault(event.type(), List.of());
        for (EventListener listener : subscribers) {
            try {
                listener.onEvent(event);
            } catch (Exception e) {
                // A misbehaving subscriber must never take down the bus or
                // other subscribers.
                log.error("Listener threw while handling " + event.type(), e);
            }
        }
    }
}
