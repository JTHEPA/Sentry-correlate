package com.jojo.sentrycorrelate.resilience;

import com.jojo.sentrycorrelate.util.SimpleLogger;

import java.util.concurrent.Callable;

/**
 * Fixed-attempt retry with linear backoff, for transient failures (a
 * momentary DNS blip or a webhook endpoint returning a 5xx once).
 * Composed with {@link CircuitBreaker} at the call site: retries absorb
 * short blips, the breaker handles a sustained outage.
 */
public final class RetryPolicy {

    private static final SimpleLogger log = SimpleLogger.of(RetryPolicy.class);

    private final int maxAttempts;
    private final long backoffMillis;

    public RetryPolicy(int maxAttempts, long backoffMillis) {
        this.maxAttempts = maxAttempts;
        this.backoffMillis = backoffMillis;
    }

    public <T> T execute(String operationName, Callable<T> action) throws Exception {
        Exception lastFailure = null;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                return action.call();
            } catch (Exception e) {
                lastFailure = e;
                log.warn("Attempt " + attempt + "/" + maxAttempts + " for '" + operationName
                        + "' failed: " + e.getMessage());
                if (attempt < maxAttempts) {
                    Thread.sleep(backoffMillis * attempt);
                }
            }
        }
        throw lastFailure;
    }
}
