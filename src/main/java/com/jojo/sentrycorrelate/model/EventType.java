package com.jojo.sentrycorrelate.model;

/** Normalized event types produced by every {@code LogSource} adapter. */
public enum EventType {
    AUTH_FAILURE,
    AUTH_SUCCESS,
    HTTP_REQUEST,
    HTTP_NOT_FOUND,
    HTTP_SUSPICIOUS,
    FIREWALL_BLOCK,
    FIREWALL_ALLOW
}
