package com.jojo.sentrycorrelate.resilience;

public final class CircuitBreakerOpenException extends RuntimeException {
    public CircuitBreakerOpenException(String circuitName) {
        super("Circuit '" + circuitName + "' is open — call rejected fast");
    }
}
