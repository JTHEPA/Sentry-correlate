package com.jojo.sentrycorrelate.alerting;

import com.jojo.sentrycorrelate.model.Alert;
import com.jojo.sentrycorrelate.util.SimpleLogger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * Appends every alert to a JSON-lines file, giving the system a durable,
 * greppable audit trail independent of whatever else is subscribed
 * (useful if the webhook channel is down or nobody was watching the
 * console at the time).
 */
public final class FileAlertChannel implements AlertChannel {

    private static final SimpleLogger log = SimpleLogger.of(FileAlertChannel.class);

    private final Path outputFile;

    public FileAlertChannel(Path outputFile) {
        this.outputFile = outputFile;
    }

    @Override
    public synchronized void send(Alert alert) {
        try {
            Files.writeString(outputFile, alert.toJson() + System.lineSeparator(),
                    StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            log.error("Failed to append alert to " + outputFile, e);
        }
    }

    @Override
    public String channelName() {
        return "file";
    }
}
