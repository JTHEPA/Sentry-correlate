package com.jojo.sentrycorrelate.geo;

import java.util.Map;
import java.util.Optional;

/**
 * Stand-in for a real GeoIP integration (MaxMind GeoLite2, ipinfo.io, etc.).
 * Resolves an IP's /24-ish network prefix to a country using a small static
 * table so the project has no external service dependency and works
 * offline. Swapping {@link #countryFor(String)}'s implementation for a real
 * MaxMind database lookup is the only change needed to go from demo to
 * production — {@link com.jojo.sentrycorrelate.correlation.GeoAnomalyRule}
 * doesn't care how the answer was obtained.
 *
 * The IP ranges used in sample data (203.0.113.0/24, 198.51.100.0/24,
 * 192.0.2.0/24) are the IANA-reserved TEST-NET ranges (RFC 5737); they are
 * given fictional country assignments here purely for demo purposes.
 */
public final class GeoIpLookup {

    private static final Map<String, String> NETWORK_TO_COUNTRY = Map.of(
            "203.0.113", "South Africa",
            "198.51.100", "Russia",
            "192.0.2", "Brazil",
            "10.0", "Internal Network",
            "127.0", "Localhost"
    );

    public Optional<String> countryFor(String ip) {
        String[] octets = ip.split("\\.");
        if (octets.length < 3) {
            return Optional.empty();
        }
        String network = octets[0] + "." + octets[1] + "." + octets[2];
        String twoOctetNetwork = octets[0] + "." + octets[1];

        if (NETWORK_TO_COUNTRY.containsKey(network)) {
            return Optional.of(NETWORK_TO_COUNTRY.get(network));
        }
        if (NETWORK_TO_COUNTRY.containsKey(twoOctetNetwork)) {
            return Optional.of(NETWORK_TO_COUNTRY.get(twoOctetNetwork));
        }
        return Optional.empty();
    }
}
