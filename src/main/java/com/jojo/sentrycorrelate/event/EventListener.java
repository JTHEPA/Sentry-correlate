package com.jojo.sentrycorrelate.event;

@FunctionalInterface
public interface EventListener {
    void onEvent(Event event);
}
