package com.jojo.sentrycorrelate;

import java.lang.reflect.Method;
import java.util.List;

/**
 * A deliberately tiny test runner: no JUnit/TestNG dependency, consistent
 * with the rest of the project's zero-dependency philosophy.
 *
 * Convention: any public no-arg method named "testXxx" on a registered
 * class is a test case. A thrown {@link AssertionError} (via {@link Assert})
 * is reported as a failure; anything else thrown is reported as an error
 * rather than killing the whole run.
 */
public final class TestRunner {

    public static void main(String[] args) throws Exception {
        List<Class<?>> testClasses = List.of(
                EventWindowStoreTest.class,
                BruteForceRuleTest.class,
                CompromiseAfterBruteForceRuleTest.class,
                WebScanRuleTest.class,
                GeoAnomalyRuleTest.class,
                AlertDispatcherTest.class,
                SshAuthLogAdapterTest.class,
                WebAccessLogAdapterTest.class,
                FirewallLogAdapterTest.class
        );

        int passed = 0;
        int failed = 0;

        for (Class<?> testClass : testClasses) {
            Object instance = testClass.getDeclaredConstructor().newInstance();
            for (Method method : testClass.getMethods()) {
                if (!method.getName().startsWith("test") || method.getParameterCount() != 0) {
                    continue;
                }
                String label = testClass.getSimpleName() + "." + method.getName();
                try {
                    method.invoke(instance);
                    System.out.println("PASS  " + label);
                    passed++;
                } catch (Exception e) {
                    Throwable cause = e.getCause() != null ? e.getCause() : e;
                    System.out.println("FAIL  " + label + " -> " + cause);
                    failed++;
                }
            }
        }

        System.out.println();
        System.out.println(passed + " passed, " + failed + " failed");
        if (failed > 0) {
            System.exit(1);
        }
    }
}
