package com.jojo.sentrycorrelate.util;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Minimal, dependency-free logger. No SLF4J/Log4j so the project builds
 * with nothing but the JDK. Swap for a real framework if this grows past
 * a portfolio/demo scope.
 */
public final class SimpleLogger {

    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    private final String component;

    private SimpleLogger(String component) {
        this.component = component;
    }

    public static SimpleLogger of(Class<?> owner) {
        return new SimpleLogger(owner.getSimpleName());
    }

    public void info(String message) {
        log("INFO", message);
    }

    public void warn(String message) {
        log("WARN", message);
    }

    public void error(String message, Throwable t) {
        log("ERROR", message + " :: " + t);
    }

    private void log(String level, String message) {
        System.out.printf("%s [%s] %-6s %s%n",
                LocalDateTime.now().format(TS), component, level, message);
    }
}
