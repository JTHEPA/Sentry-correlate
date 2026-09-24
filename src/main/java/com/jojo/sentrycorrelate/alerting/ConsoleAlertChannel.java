package com.jojo.sentrycorrelate.alerting;

import com.jojo.sentrycorrelate.model.Alert;
import com.jojo.sentrycorrelate.util.SimpleLogger;

/** Prints alerts to stdout — the always-available fallback channel. */
public final class ConsoleAlertChannel implements AlertChannel {

    private static final SimpleLogger log = SimpleLogger.of(ConsoleAlertChannel.class);

    @Override
    public void send(Alert alert) {
        log.warn("[%s] %s :: %s".formatted(alert.severity(), alert.ruleName(), alert.summary()));
    }

    @Override
    public String channelName() {
        return "console";
    }
}
