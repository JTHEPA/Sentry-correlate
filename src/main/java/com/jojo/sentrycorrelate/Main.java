package com.jojo.sentrycorrelate;

import com.jojo.sentrycorrelate.alerting.AlertDispatcher;
import com.jojo.sentrycorrelate.alerting.AlertStore;
import com.jojo.sentrycorrelate.alerting.ConsoleAlertChannel;
import com.jojo.sentrycorrelate.alerting.FileAlertChannel;
import com.jojo.sentrycorrelate.alerting.WebhookAlertChannel;
import com.jojo.sentrycorrelate.api.SentryController;
import com.jojo.sentrycorrelate.correlation.BruteForceRule;
import com.jojo.sentrycorrelate.correlation.CompromiseAfterBruteForceRule;
import com.jojo.sentrycorrelate.correlation.CorrelationEngine;
import com.jojo.sentrycorrelate.correlation.CorrelationRule;
import com.jojo.sentrycorrelate.correlation.EventWindowStore;
import com.jojo.sentrycorrelate.correlation.GeoAnomalyRule;
import com.jojo.sentrycorrelate.correlation.WebScanRule;
import com.jojo.sentrycorrelate.event.EventBus;
import com.jojo.sentrycorrelate.geo.GeoIpLookup;
import com.jojo.sentrycorrelate.ingestion.FirewallLogAdapter;
import com.jojo.sentrycorrelate.ingestion.LogIngestionService;
import com.jojo.sentrycorrelate.ingestion.LogSource;
import com.jojo.sentrycorrelate.ingestion.SshAuthLogAdapter;
import com.jojo.sentrycorrelate.ingestion.WebAccessLogAdapter;
import com.jojo.sentrycorrelate.resilience.CircuitBreaker;
import com.jojo.sentrycorrelate.resilience.RetryPolicy;
import com.jojo.sentrycorrelate.util.SimpleLogger;

import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

/**
 * Composition root. This is the only class that knows every concrete
 * implementation in the system; everything downstream depends on
 * interfaces, which is what keeps ingestion, correlation and alerting
 * independently testable.
 *
 * On startup this replays the seeded attack scenario in data/*.log
 * through the correlation engine so you can see real alerts fire
 * immediately, then starts the REST API for live ingestion.
 */
public final class Main {

    private static final SimpleLogger log = SimpleLogger.of(Main.class);
    private static final int DEFAULT_PORT = 8080;

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : DEFAULT_PORT;

        EventBus eventBus = new EventBus();
        eventBus.subscribe("ALERT_RAISED", e -> log.info("[audit] alert raised: " + e.get("ruleName")
                + " (" + e.get("sourceIp") + ")"));

        // --- Correlation ---
        EventWindowStore windowStore = new EventWindowStore(Duration.ofMinutes(15));
        GeoIpLookup geoIpLookup = new GeoIpLookup();
        List<CorrelationRule> rules = List.of(
                new BruteForceRule(5, Duration.ofSeconds(60)),
                new CompromiseAfterBruteForceRule(5, Duration.ofSeconds(60)),
                new WebScanRule(5, Duration.ofMinutes(2)),
                new GeoAnomalyRule(geoIpLookup, Duration.ofMinutes(10))
        );

        // --- Alerting ---
        AlertStore alertStore = new AlertStore();
        CircuitBreaker webhookBreaker = new CircuitBreaker("alert-webhook", 3, Duration.ofSeconds(15));
        RetryPolicy webhookRetry = new RetryPolicy(2, 150);
        AlertDispatcher dispatcher = new AlertDispatcher(List.of(
                new ConsoleAlertChannel(),
                new FileAlertChannel(Path.of("alerts.jsonl")),
                new WebhookAlertChannel(URI.create("http://localhost:9/webhook"), webhookBreaker, webhookRetry)
        ), alertStore, Duration.ofMinutes(5));

        CorrelationEngine engine = new CorrelationEngine(windowStore, rules, dispatcher, eventBus);

        // --- Ingestion ---
        List<LogSource> sources = List.of(
                new SshAuthLogAdapter(), new WebAccessLogAdapter(), new FirewallLogAdapter());
        LogIngestionService ingestion = new LogIngestionService(sources, Path.of("data"));

        log.info("Replaying seeded attack scenario from data/*.log ...");
        LogIngestionService.IngestionStats stats = ingestion.replayAll(engine::process);
        log.info("Replay complete: " + stats.eventsParsed() + " events parsed, "
                + stats.linesSkipped() + " lines skipped. " + alertStore.count() + " alert(s) raised.");

        // --- REST API ---
        SentryController controller = new SentryController(engine, ingestion, alertStore);
        controller.start(port);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("Shutting down SentryCorrelate...");
            controller.stop();
        }));

        log.info("SentryCorrelate is up. Try:");
        log.info("  curl http://localhost:" + port + "/alerts");
        log.info("  curl http://localhost:" + port + "/stats");
        log.info("  curl -X POST http://localhost:" + port
                + "/events/ingest -d 'source=ssh&line=2026-09-23T10:00:00 sshd Failed password for root from 203.0.113.9 port 4000'");
    }
}
