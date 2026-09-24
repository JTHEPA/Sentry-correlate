package com.jojo.sentrycorrelate;

import com.jojo.sentrycorrelate.ingestion.WebAccessLogAdapter;
import com.jojo.sentrycorrelate.model.EventType;
import com.jojo.sentrycorrelate.model.SecurityEvent;

import java.util.Optional;

public class WebAccessLogAdapterTest {

    public void testParsesOrdinaryRequestAs200() {
        WebAccessLogAdapter adapter = new WebAccessLogAdapter();
        Optional<SecurityEvent> event = adapter.parse("2026-09-21T09:14:00 192.0.2.44 GET /index.html 200");

        Assert.isTrue(event.isPresent(), "Valid access-log line should parse");
        Assert.equals(EventType.HTTP_REQUEST, event.get().type(), "A 200 response should classify as HTTP_REQUEST");
        Assert.equals("/index.html", event.get().path(), "Path should be extracted");
    }

    public void testParsesNotFoundAs404Type() {
        WebAccessLogAdapter adapter = new WebAccessLogAdapter();
        Optional<SecurityEvent> event = adapter.parse("2026-09-21T09:14:20 192.0.2.44 GET /wp-login.php 404");

        Assert.equals(EventType.HTTP_NOT_FOUND, event.get().type(), "A 404 response should classify as HTTP_NOT_FOUND");
    }

    public void testDetectsSqlInjectionPayloadAsSuspicious() {
        WebAccessLogAdapter adapter = new WebAccessLogAdapter();
        Optional<SecurityEvent> event = adapter.parse(
                "2026-09-21T09:15:00 192.0.2.44 GET /products?id=1' OR '1'='1 200");

        Assert.isTrue(event.isPresent(), "Line with embedded spaces in the path should still parse");
        Assert.equals(EventType.HTTP_SUSPICIOUS, event.get().type(),
                "SQLi-pattern path should be flagged as HTTP_SUSPICIOUS even with a 200 response");
    }

    public void testDetectsPathTraversalAsSuspicious() {
        WebAccessLogAdapter adapter = new WebAccessLogAdapter();
        Optional<SecurityEvent> event = adapter.parse(
                "2026-09-21T09:15:00 192.0.2.44 GET /files?path=../../etc/passwd 200");

        Assert.equals(EventType.HTTP_SUSPICIOUS, event.get().type(), "Path traversal pattern should be flagged as suspicious");
    }
}
