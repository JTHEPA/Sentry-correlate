# Contributing to SentryCorrelate

This started as a learning/portfolio exercise, so these guidelines are
intentionally lightweight — the goal is a codebase that's easy to read
and easy to extend with new detections, not heavy process.

## Ground rules

- **Keep the zero-dependency philosophy.** The project builds with
  nothing but the JDK on purpose. If you want to add a library, open an
  issue first to discuss whether it's worth losing that property for.
- **Every log source is an adapter.** New log formats implement
  `LogSource` and get registered in `Main` — `LogIngestionService` and
  the correlation engine should never need to know about a specific
  format.
- **Every detection is a rule.** New attack patterns implement
  `CorrelationRule` and get registered in `Main` — see
  [README.md's extension guide](README.md#extending-it-adding-a-new-detection-rule).
- **Tag every alert with a MITRE ATT&CK technique.** Pick the closest
  fit from [attack.mitre.org](https://attack.mitre.org/techniques/enterprise/)
  — this is what makes alerts usable outside this codebase.
- **`CorrelationEngine` is the only orchestrator.** Rules should never
  call alert channels directly, and channels should never know about
  rules; go through the engine → dispatcher path.

## Getting set up

```bash
git clone <this-repo-url>
cd sentry-correlate
mvn clean package
java -jar target/sentry-correlate.jar
```

See the [README](README.md#getting-started) for the Maven-free build
path.

## Coding conventions

- Java 17+ language features are fine (records, text blocks, pattern
  matching) — the compiler target is 17.
- Favor constructor injection over static singletons; every class here
  takes its collaborators in its constructor so it can be tested in
  isolation.
- A rule should never throw on a malformed or unexpected event — return
  `Optional.empty()` instead. One bad event must never take down
  correlation for every other IP being tracked.
- New calls to a real external system (a webhook, a future real GeoIP
  API) should be wrapped in `CircuitBreaker`/`RetryPolicy` the same way
  `WebhookAlertChannel` wraps its HTTP call.

## Tests

Every new rule or adapter should ship with tests using the existing
hand-rolled `TestRunner` (see
`src/test/java/com/jojo/sentrycorrelate/TestRunner.java` for the
convention: public `testXxx()` methods, `Assert` helpers). Register any
new test class in `TestRunner.main`.

Run the suite before opening a PR:

```bash
mkdir -p out
javac -d out $(find src/main -name "*.java") $(find src/test -name "*.java")
java -cp out com.jojo.sentrycorrelate.TestRunner
```

For a new rule, also add a line or two to `data/*.log` that exercises it
so the seeded-scenario replay demonstrates the new detection too.

## Commit messages

- Imperative summary line under ~72 characters
  (`Add port-scan detection rule`, not `Added...`).
- Use the body to explain *why* a detection matters (what it catches,
  why the threshold/window was chosen), not just what changed — the diff
  already shows that.

## Submitting changes

1. Fork the repo and create a branch off `main`.
2. Make your change, with tests, following the conventions above.
3. Confirm `mvn clean package` (or the javac equivalent) succeeds and
   the test suite passes.
4. Open a pull request describing the attack pattern or improvement and
   its motivation.

## Reporting issues

Please include: the log line(s) or scenario that should have triggered
(or shouldn't have triggered) a rule, what happened instead, and the
smallest reproduction you can manage.
