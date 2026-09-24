# SentryCorrelate

A security-log correlation and alerting engine, built in Java, that does
the job a junior SOC analyst spends a lot of their shift doing by hand:
watching multiple log sources, noticing when events across them form an
attack pattern, and raising a triage-ready alert instead of three
unrelated log lines.

Zero third-party dependencies — it builds and runs with nothing but the
JDK, which makes it easy to clone, read, and run anywhere, including
offline.

---

## Table of contents

- [The problem this solves](#the-problem-this-solves)
- [What it actually detects](#what-it-actually-detects)
- [Architecture](#architecture)
- [Design patterns used](#design-patterns-used)
- [Project structure](#project-structure)
- [Getting started](#getting-started)
- [Try it: the seeded attack scenario](#try-it-the-seeded-attack-scenario)
- [API reference](#api-reference)
- [Running the tests](#running-the-tests)
- [Resilience behaviour](#resilience-behaviour)
- [Extending it: adding a new detection rule](#extending-it-adding-a-new-detection-rule)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## The problem this solves

In a real SOC, SSH auth logs, web server access logs, and firewall logs
usually live in different places, in different formats, watched (if at
all) by different tools. A single failed SSH login means nothing. A
single 404 on a web server means nothing. But five failed SSH logins in
ten seconds, followed by a successful one, from an IP that's also hitting
`/wp-login.php`, `/.env`, and `/phpmyadmin` — that's a story, and it's a
story that only becomes visible once you correlate *across* sources and
*across* time.

That correlation step is exactly what SentryCorrelate does:

| Log source | Format modelled here | Real-world equivalent |
|---|---|---|
| SSH auth | `data/ssh.log` | `/var/log/auth.log`, `journalctl -u sshd` |
| Web access | `data/web.log` | Nginx/Apache combined log |
| Firewall | `data/firewall.log` | iptables/pf logs, a NGFW's connection log |

Every event, regardless of source, is normalized into one
`SecurityEvent` model and fed into a correlation engine that runs a set
of detection rules against a rolling time window, per source IP.

## What it actually detects

Every alert is tagged with a [MITRE ATT&CK](https://attack.mitre.org/)
technique ID — the reference framework SOC analysts, SIEMs, and case
management tools already use to classify adversary behaviour, so an
alert from this engine slots into the same vocabulary as an alert from
Splunk, Sentinel, or Elastic Security.

| Rule | Detects | Severity | MITRE technique |
|---|---|---|---|
| `brute-force-auth` | N failed logins from one IP in a short window | HIGH | T1110 — Brute Force |
| `compromise-after-brute-force` | A **successful** login right after a failed burst from the same IP | CRITICAL | T1078 — Valid Accounts |
| `web-recon-scan` | A burst of 404s from one IP (endpoint enumeration) | MEDIUM | T1595 — Active Scanning |
| `suspicious-payload` | A single request matching a SQLi/path-traversal/XSS pattern | HIGH | T1190 — Exploit Public-Facing Application |
| `impossible-travel` | The same user logging in from two countries too fast to have travelled | CRITICAL | T1078.004 — Valid Accounts: Cloud Accounts |

`compromise-after-brute-force` is the highest-value case in the system:
neither the failures alone nor the single success alone are that
interesting, but together, in a short window, they strongly suggest the
password guessing worked — which is a materially different and more
urgent finding than "someone mistyped their password five times."

## Architecture
WTC-L6U53ZB7

```
  data/ssh.log ──┐
  data/web.log ──┼──▶ LogSource adapters ──▶ SecurityEvent (normalized)
  data/firewall.log ┘        │
  POST /events/ingest ───────┘  (same adapters, for live feeds)
                              │
                              ▼
                    ┌──────────────────────┐
                    │   CorrelationEngine    │  ◀── composition root: Main.java
                    │  (records to window,    │
                    │   runs every rule)       │
                    └──────────┬───────────┘
                    EventWindowStore (per-IP, time-bounded)
                               │
              ┌────────────────┼────────────────┬───────────────┐
              ▼                ▼                ▼               ▼
      BruteForceRule   CompromiseAfter-   WebScanRule    GeoAnomalyRule
                        BruteForceRule
              │                │                │               │
              └────────────────┴────────────────┴───────────────┘
                               │ Alert (MITRE-tagged)
                               ▼
                    ┌──────────────────────┐
                    │    AlertDispatcher     │  dedup/suppression window
                    └──┬─────────┬────────┬──┘
                       ▼         ▼        ▼
                  Console      File    Webhook (circuit breaker + retry)
                                          │
                                    GET /alerts, /alerts/{id}, /stats
```

`CorrelationEngine` is the only class that talks to both the window
store and every rule — adapters never know about rules, and rules never
know about alerting channels. That seam is what makes each layer
independently testable (see `src/test`) and independently replaceable
(swap the CSV-ish log files for a real syslog/Kafka feed, or the console
channel for a real Slack webhook, without touching the rules).

## Design patterns used

- **Adapter** — `LogSource` gives every log format (SSH/web/firewall) a
  common `parse()` contract; `AlertChannel` does the same for outbound
  delivery (console/file/webhook).
- **Strategy / extension point** — `CorrelationRule` is what you
  implement to add a new detection; the engine doesn't change.
- **Circuit breaker + retry** — protects the webhook alert channel from
  a slow or unreachable endpoint. Verified in testing: pointing it at an
  unreachable address causes the breaker to trip OPEN after 3 consecutive
  failures, exactly as designed, while alerts keep reaching the
  console/file channels.
- **Publish/subscribe** — `EventBus` decouples "an alert was raised" from
  whoever reacts to it (currently an audit log line; a ticketing-system
  integration would subscribe the same way).
- **Composition root** — `Main` is the only class referencing concrete
  implementations; everything else depends on interfaces.

## Project structure

```
sentry-correlate/
├── pom.xml
├── data/
│   ├── ssh.log                # seed SSH auth log (brute force -> compromise)
│   ├── web.log                # seed web access log (recon scan + SQLi probe)
│   └── firewall.log           # seed firewall log (corroborating evidence)
├── src/main/java/com/jojo/sentrycorrelate/
│   ├── Main.java               # composition root
│   ├── model/                  # SecurityEvent, EventType, Severity, Alert
│   ├── ingestion/               # LogSource + Ssh/Web/Firewall adapters, LogIngestionService
│   ├── correlation/             # EventWindowStore, CorrelationRule + the 4 rules, CorrelationEngine
│   ├── alerting/                 # AlertChannel + Console/File/Webhook, AlertDispatcher, AlertStore
│   ├── geo/                     # GeoIpLookup (documented stand-in for a real GeoIP service)
│   ├── api/                     # SentryController (REST)
│   ├── event/                   # EventBus (internal pub/sub)
│   └── resilience/               # CircuitBreaker, RetryPolicy
└── src/test/java/com/jojo/sentrycorrelate/
    ├── TestRunner.java, Assert.java   # tiny zero-dependency test harness
    └── ...Test.java                   # 33 tests across every layer
```

## Getting started

### Prerequisites

- JDK 17+ (developed and tested against JDK 21)
- Maven 3.8+ (optional — see the javac-only path below)

### Build & run with Maven

```bash
mvn clean package
java -jar target/sentry-correlate.jar
# or on a custom port:
java -jar target/sentry-correlate.jar 9090
```

### Build & run with plain javac (no Maven needed)

```bash
mkdir -p out
javac -d out $(find src/main -name "*.java")
java -cp out com.jojo.sentrycorrelate.Main
```

## Try it: the seeded attack scenario

`data/*.log` is pre-loaded with a realistic multi-stage scenario. On
startup the engine replays it and you'll see real alerts fire in the
console immediately — no setup needed:

```
[HIGH]     brute-force-auth            :: 5 failed authentication attempts from 203.0.113.5 within 60s
[CRITICAL] compromise-after-brute-force :: Successful login for 'admin' from 203.0.113.5 followed 5 failed attempts — credentials likely compromised
[CRITICAL] impossible-travel            :: User 'admin' logged in from 203.0.113.5 (South Africa) then from 198.51.100.99 (Russia) only 90s later
[MEDIUM]   web-recon-scan               :: 5 distinct not-found requests from 192.0.2.44 — likely endpoint enumeration
[HIGH]     suspicious-payload           :: Suspicious payload in request from 192.0.2.44: /products?id=1' OR '1'='1
```

You'll also see the webhook channel's `RetryPolicy` exhaust its attempts
and the `CircuitBreaker` trip OPEN — because `data/`'s default webhook
URL is intentionally unreachable in a local run, which is a genuine
demonstration of the resilience pattern working, not a bug. Alerts still
land in `alerts.jsonl` and the console regardless.

Then feed it a live event yourself:

```bash
curl -X POST http://localhost:8080/events/ingest \
  -d 'source=ssh&line=2026-09-23T10:00:00 sshd Failed password for root from 203.0.113.9 port 4000'

curl http://localhost:8080/alerts
curl http://localhost:8080/stats
```

## API reference

| Method | Path | Body | Description |
|---|---|---|---|
| `GET`  | `/health` | — | Liveness check + total alert count |
| `GET`  | `/stats` | — | Events processed per source, alerts raised per rule |
| `POST` | `/events/ingest` | `source=<ssh\|web\|firewall>&line=<raw log line>` | Feeds one line through the matching adapter into the live engine |
| `GET`  | `/alerts` | — | All raised alerts, most recent first |
| `GET`  | `/alerts/{id}` | — | A single alert by id |

## Running the tests

No test framework dependency — consistent with the rest of the project:

```bash
mkdir -p out
javac -d out $(find src/main -name "*.java") $(find src/test -name "*.java")
java -cp out com.jojo.sentrycorrelate.TestRunner
```

33 tests cover event windowing/pruning, all four correlation rules
(including their MITRE tags), alert dispatcher suppression and
channel-failure isolation, and all three log adapters' parsing —
including malformed input and the SQLi/path-traversal detection.

## Resilience behaviour

The webhook alert channel is the one piece of this system that talks to
a real network endpoint, and it's wrapped accordingly:

1. **`RetryPolicy`** (2 attempts, linear backoff) absorbs a momentary
   blip.
2. **`CircuitBreaker`** (trips after 3 consecutive failures, 15s
   cool-down) stops hammering an endpoint that's genuinely down, so a
   flood of alerts during an actual incident doesn't also become a
   self-inflicted denial-of-service against your own webhook.

Console and file delivery are unaffected either way — a down webhook
should never mean a SOC analyst misses an alert entirely.

## Extending it: adding a new detection rule

1. Implement `CorrelationRule` (`name()` + `evaluate(event, store)`).
2. Query `EventWindowStore.recentFor(ip, window, now, filter)` for
   whatever pattern you're after.
3. Return an `Alert` with an appropriate `Severity` and MITRE technique
   ID when the pattern matches, `Optional.empty()` otherwise.
4. Register it in `Main`'s `rules` list.
5. Add a test class and register it in `TestRunner`.

No other class needs to change — that's the point of the rule extension
point.

## Roadmap

- [ ] A minimal HTML dashboard (alert feed + stats) served alongside the
  JSON API, for a more SOC-console-like feel
- [ ] Swap the flat-file log sources for real-time file tailing
  (`WatchService`) instead of startup-only replay
- [ ] A rule combining firewall BLOCK bursts with web/SSH activity from
  the same IP for stronger corroboration
- [ ] JUnit 5 + Surefire alongside the current dependency-free runner
- [ ] A Dockerfile for a one-command run

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for coding conventions and the PR
process.

## License

Released under the [MIT License](LICENSE).

---

