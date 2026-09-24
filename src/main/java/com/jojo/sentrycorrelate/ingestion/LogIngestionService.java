package com.jojo.sentrycorrelate.ingestion;

import com.jojo.sentrycorrelate.model.SecurityEvent;
import com.jojo.sentrycorrelate.util.SimpleLogger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * Reads log files through their matching {@link LogSource} adapter and
 * hands every successfully-parsed {@link SecurityEvent} to a consumer
 * (normally {@code CorrelationEngine::process}).
 *
 * This class only knows about the {@link LogSource} interface, never a
 * concrete adapter — adding a fourth log source (say, a cloud audit log)
 * means writing one new adapter class and registering it, with zero
 * changes here.
 */
public final class LogIngestionService {

    private static final SimpleLogger log = SimpleLogger.of(LogIngestionService.class);

    private final List<LogSource> sources;
    private final Path dataDirectory;

    public LogIngestionService(List<LogSource> sources, Path dataDirectory) {
        this.sources = List.copyOf(sources);
        this.dataDirectory = dataDirectory;
    }

    /**
     * Replays every source's log file from disk (data/&lt;sourceSystem&gt;.log)
     * through its adapter, in file order, handing each parsed event to
     * {@code eventConsumer}. Used at startup to demonstrate detection
     * against the seeded attack scenario; {@code POST /events/ingest}
     * covers the live-feed path via the same adapters.
     */
    public IngestionStats replayAll(Consumer<SecurityEvent> eventConsumer) {
        int totalParsed = 0;
        int totalSkipped = 0;

        for (LogSource source : sources) {
            Path file = dataDirectory.resolve(source.sourceSystem() + ".log");
            if (!Files.exists(file)) {
                log.warn("No log file found for source '" + source.sourceSystem() + "' at " + file);
                continue;
            }
            try {
                List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
                int parsed = 0, skipped = 0;
                for (String line : lines) {
                    Optional<SecurityEvent> event = source.parse(line);
                    if (event.isPresent()) {
                        eventConsumer.accept(event.get());
                        parsed++;
                    } else if (!line.isBlank()) {
                        skipped++;
                    }
                }
                log.info("Replayed " + parsed + " events from " + file + " (" + skipped + " unparsable lines skipped)");
                totalParsed += parsed;
                totalSkipped += skipped;
            } catch (IOException e) {
                log.error("Failed to read log file " + file, e);
            }
        }
        return new IngestionStats(totalParsed, totalSkipped);
    }

    /** Finds the adapter registered for a given source system name, e.g. "ssh". */
    public Optional<LogSource> sourceFor(String sourceSystem) {
        return sources.stream().filter(s -> s.sourceSystem().equalsIgnoreCase(sourceSystem)).findFirst();
    }

    public record IngestionStats(int eventsParsed, int linesSkipped) {}
}
