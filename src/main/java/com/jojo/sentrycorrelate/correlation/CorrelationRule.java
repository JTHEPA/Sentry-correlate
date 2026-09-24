package com.jojo.sentrycorrelate.correlation;

import com.jojo.sentrycorrelate.model.Alert;
import com.jojo.sentrycorrelate.model.SecurityEvent;

import java.util.Optional;

/**
 * A single detection rule evaluated against every incoming event. Rules
 * are the extension point of the whole system: adding a new attack
 * pattern means implementing this interface and registering it in
 * {@code Main} — nothing else in the engine changes.
 */
public interface CorrelationRule {

    /** A stable identifier used in alerts and de-duplication, e.g. "brute-force-ssh". */
    String name();

    /**
     * Inspects the newly-recorded event (already added to {@code store})
     * and returns an {@link Alert} if this rule's pattern is now matched.
     */
    Optional<Alert> evaluate(SecurityEvent event, EventWindowStore store);
}
