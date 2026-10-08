package individuals.Jimmy;
import java.io.*;

/**
 * IT355 Group Project 1 - Recommendations & Rules Demos:
 * MET50-J, MET53-J, ERR54-J, SER05-J, MET06-J, MET12-J, MET05-J, and ERR01-J.
 * 
 * @author Jimmy Motsch
 */
public class JimmyRulesDemo {

    /**
     * MET50-J: Avoid ambiguous or confusing uses of overloading.
     * Keep overloaded methods distinct to prevent compiler ambiguity or unexpected resolution.
     */
    static final class Calculator {
        /** @param x integer value */
        public void printValue(int x) {
            System.out.println("  [MET50-J] Processing integer: " + x);
        }

        /** @param text string value */
        public void printValue(String text) {
            System.out.println("  [MET50-J] Processing string: " + text);
        }
    }

    /**
     * MET53-J: Ensure that the clone() method calls super.clone().
     * Guarantees correct object creation mechanism rather than manual instantiation.
     */
    static final class DataRecord implements Cloneable {
        private int id;

        DataRecord(int id) {
            this.id = id;
        }

        @Override
        public Object clone() throws CloneNotSupportedException {
            System.out.println("  [MET53-J] Delegating clone() to super.clone()");
            return super.clone();
        }

        public int getId() {
            return id;
        }
    }

    /**
     * ERR54-J: Use a try-with-resources statement to safely handle closeable resources.
     * Prevents resource leaks by auto-closing streams.
     */
    static final class FileReaderUtil {
        /** @param filePath path to read */
        public static String readFirstLine(String filePath) {
            try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
                System.out.println("  [ERR54-J] Successfully opened resource via try-with-resources");
                return reader.readLine();
            } catch (IOException e) {
                System.out.println("  [ERR54-J] Handled resource error safely");
                return null;
            }
        }
    }

    /**
     * SER05-J: Do not serialize instances of inner classes.
     * Use static nested classes instead to avoid hidden outer reference issues.
     */
    public static class SafeNestedClass implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;
        private String data = "Safe static nested data";

        public String getData() {
            return data;
        }
    }

    /**
     * MET06-J: Do not invoke overridable methods in clone().
     * Helper methods called during cloning must be final or private.
     */
    static final class SecureCloneDemo implements Cloneable {
        private int state = 50;

        private final void resetState() {
            this.state = 50;
        }

        @Override
        public Object clone() throws CloneNotSupportedException {
            SecureCloneDemo copy = (SecureCloneDemo) super.clone();
            copy.resetState();
            System.out.println("  [MET06-J] Cloned safely using private final helper");
            return copy;
        }
    }

    /**
     * MET12-J: Do not use finalizers.
     * Rely on explicit resource management via AutoCloseable instead.
     */
    static final class ExplicitResource implements AutoCloseable {
        @Override
        public void close() {
            System.out.println("  [MET12-J] Explicitly cleaned up resource (no finalizer)");
        }
    }

    /**
     * MET05-J: Ensure that constructors do not call overridable methods.
     * Helper initialization methods should be private or final.
     */
    static final class BaseClass {
        BaseClass() {
            init();
        }

        private final void init() {
            System.out.println("  [MET05-J] Constructor invoked private final init()");
        }
    }

    /**
     * ERR01-J: Do not allow exceptions to expose sensitive information.
     * Catch low-level exceptions and throw sanitized messages.
     */
    static final class InputParser {
        public static void parse(String input) {
            try {
                Integer.parseInt(input);
            } catch (NumberFormatException e) {
                System.out.println("  [ERR01-J] Caught internal parse error, throwing sanitized message");
                throw new IllegalArgumentException("Invalid input format provided.");
            }
        }
    }

    /** Runs a demo for each rule and recommendation. */
    public static void main(String[] args) throws Exception {
        System.out.println("=== MET50-J: Distinct overloads ===");
        new Calculator().printValue(100);

        System.out.println("\n=== MET53-J: super.clone() ===");
        DataRecord original = new DataRecord(42);
        DataRecord copy = (DataRecord) original.clone();
        System.out.println("  Cloned ID: " + copy.getId());

        System.out.println("\n=== ERR54-J: Try-with-resources ===");
        FileReaderUtil.readFirstLine("nonexistent.txt");

        System.out.println("\n=== SER05-J: Static nested class serialization ===");
        SafeNestedClass nested = new SafeNestedClass();
        System.out.println("  Nested data: " + nested.getData());

        System.out.println("\n=== MET06-J: Safe clone with final helper ===");
        new SecureCloneDemo().clone();

        System.out.println("\n=== MET12-J: Explicit AutoCloseable ===");
        try (ExplicitResource res = new ExplicitResource()) {
            // using resource
        }

        System.out.println("\n=== MET05-J: Constructor safety ===");
        new BaseClass();

        System.out.println("\n=== ERR01-J: Sanitized exception handling ===");
        try {
            InputParser.parse("bad-input");
        } catch (IllegalArgumentException e) {
            System.out.println("  Caught expected exception: " + e.getMessage());
        }
    }
}