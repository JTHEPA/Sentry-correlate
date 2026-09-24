package com.jojo.sentrycorrelate.api;

import com.jojo.sentrycorrelate.alerting.AlertStore;
import com.jojo.sentrycorrelate.correlation.CorrelationEngine;
import com.jojo.sentrycorrelate.ingestion.LogIngestionService;
import com.jojo.sentrycorrelate.model.Alert;
import com.jojo.sentrycorrelate.model.SecurityEvent;
import com.jojo.sentrycorrelate.util.SimpleLogger;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * REST surface over the correlation engine, built on the JDK's built-in
 * com.sun.net.httpserver so the whole project stays dependency-free.
 *
 * Endpoints:
 *   POST /events/ingest   body: source=<ssh|web|firewall>&line=<raw log line>
 *   GET  /alerts
 *   GET  /alerts/{id}
 *   GET  /stats
 *   GET  /health
 *
 * POST /events/ingest is what makes this a live system rather than a
 * one-shot batch job: it lets an external log shipper (or `curl`, for a
 * demo) feed new lines through the same adapters used at startup, so
 * detection keeps running against real-time input.
 */
public final class SentryController {

    private static final SimpleLogger log = SimpleLogger.of(SentryController.class);
    private static final Pattern ALERT_ID_PATH = Pattern.compile("^/alerts/([\\w-]+)$");

    private final CorrelationEngine engine;
    private final LogIngestionService ingestionService;
    private final AlertStore alertStore;
    private HttpServer server;

    public SentryController(CorrelationEngine engine, LogIngestionService ingestionService, AlertStore alertStore) {
        this.engine = engine;
        this.ingestionService = ingestionService;
        this.alertStore = alertStore;
    }

    public void start(int port) throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/health", this::handleHealth);
        server.createContext("/stats", this::handleStats);
        server.createContext("/events/ingest", this::handleIngest);
        server.createContext("/alerts", this::handleAlerts);
        server.setExecutor(null);
        server.start();
        log.info("SentryController listening on http://localhost:" + port);
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    private void handleHealth(HttpExchange exchange) throws IOException {
        respond(exchange, 200, "{\"status\":\"UP\",\"alertsRaised\":%d}".formatted(alertStore.count()));
    }

    private void handleStats(HttpExchange exchange) throws IOException {
        String eventsBySource = engine.eventsBySource().entrySet().stream()
                .map(e -> "\"%s\":%d".formatted(e.getKey(), e.getValue()))
                .collect(Collectors.joining(","));
        String alertsByRule = engine.alertsByRule().entrySet().stream()
                .map(e -> "\"%s\":%d".formatted(e.getKey(), e.getValue()))
                .collect(Collectors.joining(","));
        respond(exchange, 200, "{\"eventsBySource\":{%s},\"alertsByRule\":{%s}}"
                .formatted(eventsBySource, alertsByRule));
    }

    private void handleIngest(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            respond(exchange, 405, "{\"error\":\"method not allowed\"}");
            return;
        }

        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> form = parseForm(body);
        String sourceSystem = form.get("source");
        String rawLine = form.get("line");

        if (sourceSystem == null || rawLine == null) {
            respond(exchange, 400, "{\"error\":\"source and line are required\"}");
            return;
        }

        Optional<com.jojo.sentrycorrelate.ingestion.LogSource> source = ingestionService.sourceFor(sourceSystem);
        if (source.isEmpty()) {
            respond(exchange, 400, "{\"error\":\"unknown source '" + sourceSystem + "'\"}");
            return;
        }

        Optional<SecurityEvent> event = source.get().parse(rawLine);
        if (event.isEmpty()) {
            respond(exchange, 422, "{\"error\":\"line did not match the '" + sourceSystem + "' log format\"}");
            return;
        }

        engine.process(event.get());
        respond(exchange, 202, "{\"status\":\"ingested\",\"eventType\":\"" + event.get().type() + "\"}");
    }

    private void handleAlerts(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();

        if ("/alerts".equals(path)) {
            String json = alertStore.findAll().stream().map(Alert::toJson).collect(Collectors.joining(","));
            respond(exchange, 200, "[" + json + "]");
            return;
        }

        Matcher m = ALERT_ID_PATH.matcher(path);
        if (m.matches()) {
            Optional<Alert> alert = alertStore.findById(m.group(1));
            if (alert.isPresent()) {
                respond(exchange, 200, alert.get().toJson());
            } else {
                respond(exchange, 404, "{\"error\":\"alert not found\"}");
            }
            return;
        }

        respond(exchange, 404, "{\"error\":\"not found\"}");
    }

    private Map<String, String> parseForm(String body) {
        Map<String, String> result = new java.util.HashMap<>();
        for (String pair : body.split("&")) {
            if (pair.isBlank()) continue;
            String[] kv = pair.split("=", 2);
            String key = java.net.URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
            String value = kv.length > 1 ? java.net.URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "";
            result.put(key, value);
        }
        return result;
    }

    private void respond(HttpExchange exchange, int statusCode, String jsonBody) throws IOException {
        byte[] bytes = jsonBody.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
