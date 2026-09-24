package com.jojo.sentrycorrelate.alerting;

import com.jojo.sentrycorrelate.model.Alert;

/**
 * Adapter-pattern seam for outbound alert delivery. Console/file channels
 * here stand in for what would be Slack, PagerDuty, email, or a SIEM
 * ticketing API in production — {@link AlertDispatcher} treats every
 * channel identically.
 */
public interface AlertChannel {
    void send(Alert alert);

    String channelName();
}
