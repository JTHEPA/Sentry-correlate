package com.jojo.sentrycorrelate;

import com.jojo.sentrycorrelate.ingestion.FirewallLogAdapter;
import com.jojo.sentrycorrelate.model.EventType;
import com.jojo.sentrycorrelate.model.SecurityEvent;

import java.util.Optional;

public class FirewallLogAdapterTest {

    public void testParsesBlockLine() {
        FirewallLogAdapter adapter = new FirewallLogAdapter();
        Optional<SecurityEvent> event = adapter.parse("2026-09-21T09:20:00 firewall BLOCK 192.0.2.44 -> 10.0.0.5:3389");

        Assert.isTrue(event.isPresent(), "Valid BLOCK line should parse");
        Assert.equals(EventType.FIREWALL_BLOCK, event.get().type(), "Should classify as FIREWALL_BLOCK");
        Assert.equals("192.0.2.44", event.get().sourceIp(), "Source IP should be extracted");
    }

    public void testParsesAllowLine() {
        FirewallLogAdapter adapter = new FirewallLogAdapter();
        Optional<SecurityEvent> event = adapter.parse("2026-09-21T09:09:58 firewall ALLOW 203.0.113.5 -> 10.0.0.5:22");

        Assert.equals(EventType.FIREWALL_ALLOW, event.get().type(), "Should classify as FIREWALL_ALLOW");
    }

    public void testUnrecognizedLineIsSkipped() {
        FirewallLogAdapter adapter = new FirewallLogAdapter();
        Assert.isTrue(adapter.parse("garbage line").isEmpty(), "Malformed line should be skipped, not throw");
    }
}
