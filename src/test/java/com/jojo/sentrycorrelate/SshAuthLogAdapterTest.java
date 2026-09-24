package com.jojo.sentrycorrelate;

import com.jojo.sentrycorrelate.ingestion.SshAuthLogAdapter;
import com.jojo.sentrycorrelate.model.EventType;
import com.jojo.sentrycorrelate.model.SecurityEvent;

import java.util.Optional;

public class SshAuthLogAdapterTest {

    public void testParsesFailedLoginLine() {
        SshAuthLogAdapter adapter = new SshAuthLogAdapter();
        Optional<SecurityEvent> event = adapter.parse(
                "2026-09-21T09:10:00 sshd Failed password for admin from 203.0.113.5 port 51410");

        Assert.isTrue(event.isPresent(), "Valid failed-login line should parse");
        Assert.equals(EventType.AUTH_FAILURE, event.get().type(), "Should classify as AUTH_FAILURE");
        Assert.equals("admin", event.get().username(), "Username should be extracted");
        Assert.equals("203.0.113.5", event.get().sourceIp(), "Source IP should be extracted");
    }

    public void testParsesAcceptedLoginLine() {
        SshAuthLogAdapter adapter = new SshAuthLogAdapter();
        Optional<SecurityEvent> event = adapter.parse(
                "2026-09-21T09:10:30 sshd Accepted password for admin from 203.0.113.5 port 51420");

        Assert.isTrue(event.isPresent(), "Valid accepted-login line should parse");
        Assert.equals(EventType.AUTH_SUCCESS, event.get().type(), "Should classify as AUTH_SUCCESS");
    }

    public void testUnrecognizedLineIsSkippedNotThrown() {
        SshAuthLogAdapter adapter = new SshAuthLogAdapter();
        Optional<SecurityEvent> event = adapter.parse("not a valid log line at all");

        Assert.isTrue(event.isEmpty(), "Malformed line should be skipped, not throw");
    }

    public void testBlankLineIsSkipped() {
        SshAuthLogAdapter adapter = new SshAuthLogAdapter();
        Assert.isTrue(adapter.parse("").isEmpty(), "Blank line should be skipped");
        Assert.isTrue(adapter.parse(null).isEmpty(), "Null line should be skipped");
    }
}
