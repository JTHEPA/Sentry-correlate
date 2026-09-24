package com.jojo.sentrycorrelate.resilience;

import com.jojo.sentrycorrelate.util.SimpleLogger;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Three-state circuit breaker (CLOSED -> OPEN -> HALF_OPEN) protecting a
 * downstream call.
 *
 * In this system it guards the webhook alert channel: if the on-call
 * webhook (e.g. Slack/PagerDuty) is down, we don't want every subsequent
 * alert to block on a timeout — the breaker trips and alerts still reach
 * the console/file channels while the webhook is failing fast.
 */
public final class CircuitBreaker {

    public enum State { CLOSED, OPEN, HALF_OPEN }

    private static final SimpleLogger log = SimpleLogger.of(CircuitBreaker.class);

    private final String name;
    private final int failureThreshold;
    private final Duration coolDown;

    private final AtomicReference<State> state = new AtomicReference<>(State.CLOSED);
    private final AtomicInteger consecutiveFailures = new AtomicInteger(0);
    private volatile Instant openedAt = Instant.EPOCH;

    public CircuitBreaker(String name, int failureThreshold, Duration coolDown) {
        this.name = name;
        this.failureThreshold = failureThreshold;
        this.coolDown = coolDown;
    }

    public <T> T call(Callable<T> action) throws Exception {
        if (state.get() == State.OPEN) {
            if (Duration.between(openedAt, Instant.now()).compareTo(coolDown) >= 0) {
                state.set(State.HALF_OPEN);
                log.info("Circuit '" + name + "' moving OPEN -> HALF_OPEN (trial call)");
            } else {
                throw new CircuitBreakerOpenException(name);
            }
        }

        try {
            T result = action.call();
            onSuccess();
            return result;
        } catch (Exception e) {
            onFailure();
            throw e;
        }
    }

    private void onSuccess() {
        consecutiveFailures.set(0);
        if (state.compareAndSet(State.HALF_OPEN, State.CLOSED)) {
            log.info("Circuit '" + name + "' recovered: HALF_OPEN -> CLOSED");
        }
    }

    private void onFailure() {
        int failures = consecutiveFailures.incrementAndGet();
        if (state.get() == State.HALF_OPEN || failures >= failureThreshold) {
            state.set(State.OPEN);
            openedAt = Instant.now();
            log.warn("Circuit '" + name + "' tripped OPEN after " + failures + " consecutive failures");
        }
    }

    public State state() {
        return state.get();
    }

    public String name() {
        return name;
    }
}
