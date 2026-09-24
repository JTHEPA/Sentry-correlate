package com.jojo.sentrycorrelate;

import com.jojo.sentrycorrelate.correlation.EventWindowStore;
import com.jojo.sentrycorrelate.correlation.WebScanRule;
import com.jojo.sentrycorrelate.model.Alert;
import com.jojo.sentrycorrelate.model.EventType;
import com.jojo.sentrycorrelate.model.SecurityEvent;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

public class WebScanRuleTest {

    public void testSuspiciousPayloadAlertsImmediately() {
        WebScanRule rule = new WebScanRule(10, Duration.ofMinutes(2));
        EventWindowStore store = new EventWindowStore(Duration.ofMinutes(10));

        SecurityEvent sqli = new SecurityEvent(Instant.now(), "web", EventType.HTTP_SUSPICIOUS,
                "9.9.9.9", null, "/products?id=1' OR '1'='1", "raw");
        store.record(sqli);
        Optional<Alert> alert = rule.evaluate(sqli, store);

        Assert.isTrue(alert.isPresent(), "A single suspicious payload should alert immediately, not wait for a threshold");
        Assert.equals("suspicious-payload", alert.get().ruleName(), "Rule name should be suspicious-payload");
        Assert.equals("T1190 (Exploit Public-Facing Application)", alert.get().mitreTechnique(), "Should carry T1190");
    }

    public void testNotFoundBurstAlertsAtThreshold() {
        WebScanRule rule = new WebScanRule(3, Duration.ofMinutes(2));
        EventWindowStore store = new EventWindowStore(Duration.ofMinutes(10));
        Instant base = Instant.parse("2026-01-01T00:00:00Z");

        Optional<Alert> alert = Optional.empty();
        String[] paths = {"/admin.php", "/.env", "/wp-login.php"};
        for (int i = 0; i < paths.length; i++) {
            SecurityEvent e = new SecurityEvent(base.plusSeconds(i * 2), "web", EventType.HTTP_NOT_FOUND,
                    "9.9.9.9", null, paths[i], "raw");
            store.record(e);
            alert = rule.evaluate(e, store);
        }

        Assert.isTrue(alert.isPresent(), "3 distinct 404s within the window should trip the recon-scan rule");
        Assert.equals("web-recon-scan", alert.get().ruleName(), "Rule name should be web-recon-scan");
        Assert.equals("T1595 (Active Scanning)", alert.get().mitreTechnique(), "Should carry T1595");
    }

    public void testFewNotFoundsDoNotAlert() {
        WebScanRule rule = new WebScanRule(5, Duration.ofMinutes(2));
        EventWindowStore store = new EventWindowStore(Duration.ofMinutes(10));

        SecurityEvent e = new SecurityEvent(Instant.now(), "web", EventType.HTTP_NOT_FOUND,
                "9.9.9.9", null, "/favicon.ico", "raw");
        store.record(e);

        Assert.isTrue(rule.evaluate(e, store).isEmpty(), "A single 404 should not look like scanning");
    }

    public void testOrdinaryRequestsDoNotAlert() {
        WebScanRule rule = new WebScanRule(1, Duration.ofMinutes(2));
        EventWindowStore store = new EventWindowStore(Duration.ofMinutes(10));

        SecurityEvent e = new SecurityEvent(Instant.now(), "web", EventType.HTTP_REQUEST,
                "9.9.9.9", null, "/index.html", "raw");
        store.record(e);

        Assert.isTrue(rule.evaluate(e, store).isEmpty(), "A normal 200 request should never alert");
    }
}
