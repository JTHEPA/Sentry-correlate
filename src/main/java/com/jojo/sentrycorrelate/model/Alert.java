package com.jojo.sentrycorrelate.model;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * An alert raised by a {@code CorrelationRule} after it recognized a
 * pattern across one or more {@link SecurityEvent}s.
 *
 * Every alert is tagged with a MITRE ATT&amp;CK technique ID
 * ({@link #mitreTechnique()}) — the industry-standard reference SOC
 * analysts use to classify adversary behaviour, prioritize triage, and
 * write up incidents in a way other analysts and tooling (SIEMs, case
 * management systems) already understand.
 */
public final class Alert {

    private final String id;
    private final String ruleName;
    private final Severity severity;
    private final String sourceIp;
    private final String summary;
    private final String mitreTechnique;
    private final Instant triggeredAt;
    private final List<String> evidenceEventIds;

    public Alert(String ruleName, Severity severity, String sourceIp,
                 String summary, String mitreTechnique, List<String> evidenceEventIds) {
        this.id = UUID.randomUUID().toString();
        this.ruleName = ruleName;
        this.severity = severity;
        this.sourceIp = sourceIp;
        this.summary = summary;
        this.mitreTechnique = mitreTechnique;
        this.evidenceEventIds = List.copyOf(evidenceEventIds);
        this.triggeredAt = Instant.now();
    }

    public String id() { return id; }
    public String ruleName() { return ruleName; }
    public Severity severity() { return severity; }
    public String sourceIp() { return sourceIp; }
    public String summary() { return summary; }
    public String mitreTechnique() { return mitreTechnique; }
    public Instant triggeredAt() { return triggeredAt; }
    public List<String> evidenceEventIds() { return evidenceEventIds; }

    /** A key used to de-duplicate repeated alerts of the same kind from the same source. */
    public String dedupeKey() {
        return ruleName + "::" + sourceIp;
    }

    public String toJson() {
        return """
                {"id":"%s","ruleName":"%s","severity":"%s","sourceIp":"%s","summary":"%s","mitreTechnique":"%s","triggeredAt":"%s","evidenceCount":%d}"""
                .formatted(id, ruleName, severity, sourceIp,
                        summary.replace("\"", "'"), mitreTechnique, triggeredAt, evidenceEventIds.size());
    }
}
