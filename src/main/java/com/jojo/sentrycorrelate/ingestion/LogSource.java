package com.jojo.sentrycorrelate.ingestion;

import com.jojo.sentrycorrelate.model.SecurityEvent;

import java.util.Optional;

/**
 * The Adapter-pattern seam between a raw log format and the normalized
 * {@link SecurityEvent} model. Each real-world log source (SSH auth log,
 * web server access log, firewall log — and later, a cloud provider's
 * audit log, a Kubernetes audit log, etc.) implements this the same way,
 * so {@link LogIngestionService} and the correlation engine never need to
 * know the source-specific format.
 */
public interface LogSource {

    /** A short identifier used in normalized events, e.g. "ssh", "web", "firewall". */
    String sourceSystem();

    /**
     * Parses one raw log line into a {@link SecurityEvent}. Returns
     * {@code Optional.empty()} for lines that don't match this source's
     * format (e.g. blank lines, comments, or a format this adapter doesn't
     * recognize) rather than throwing — a malformed line should never take
     * down ingestion of the rest of the file.
     */
    Optional<SecurityEvent> parse(String rawLine);
}
