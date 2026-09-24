package com.jojo.sentrycorrelate.alerting;

import com.jojo.sentrycorrelate.model.Alert;
import com.jojo.sentrycorrelate.resilience.CircuitBreaker;
import com.jojo.sentrycorrelate.resilience.RetryPolicy;
import com.jojo.sentrycorrelate.util.SimpleLogger;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Posts each alert to an on-call webhook (Slack/PagerDuty/Opsgenie-style
 * incoming webhook). This is the one channel that talks to a real network
 * endpoint, which is exactly why it's the one wrapped in
 * {@link RetryPolicy} + {@link CircuitBreaker}: a slow or unreachable
 * webhook must never block or take down alert delivery on the other
 * channels.
 *
 * If no reachable webhook is configured (the common case for a local demo
 * run — see README), calls will fail, retries will exhaust, and the
 * breaker will trip OPEN after a few alerts — which is the resilience
 * behaviour working as designed, not a bug. Alerts still reach the
 * console and file channels regardless.
 */
public final class WebhookAlertChannel implements AlertChannel {

    private static final SimpleLogger log = SimpleLogger.of(WebhookAlertChannel.class);

    private final URI webhookUri;
    private final HttpClient httpClient;
    private final CircuitBreaker circuitBreaker;
    private final RetryPolicy retryPolicy;

    public WebhookAlertChannel(URI webhookUri, CircuitBreaker circuitBreaker, RetryPolicy retryPolicy) {
        this.webhookUri = webhookUri;
        this.circuitBreaker = circuitBreaker;
        this.retryPolicy = retryPolicy;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(500))
                .build();
    }

    @Override
    public void send(Alert alert) {
        try {
            retryPolicy.execute("webhook-post", () -> circuitBreaker.call(() -> postToWebhook(alert)));
        } catch (Exception e) {
            log.warn("Webhook delivery failed for alert " + alert.id() + " (circuit: "
                    + circuitBreaker.state() + "): " + e.getMessage());
        }
    }

    private Void postToWebhook(Alert alert) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(webhookUri)
                .timeout(Duration.ofSeconds(2))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(alert.toJson()))
                .build();
        HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
        if (response.statusCode() >= 300) {
            throw new IllegalStateException("Webhook returned HTTP " + response.statusCode());
        }
        log.info("Webhook delivered alert " + alert.id());
        return null;
    }

    @Override
    public String channelName() {
        return "webhook";
    }
}
