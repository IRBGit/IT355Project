import java.io.*;
import java.security.*;
import java.util.ArrayList;

/**
 * IT355 Group Project 1 - demos for MET00-J, MET01-J, SER01-J, SER04-J, and SER08-J.
 * Note: Java 24+ turns off the Security Manager, so its checks below don't do anything there.
 *
 * @author James Strickert
 */
@SuppressWarnings("removal") // SecurityManager is deprecated
public class TeamProjectDemo {
    //Start of James' Section
    /**
     * MET00-J: Validate method arguments.
     * Check inputs before using them so bad data never gets stored.
     */
    static final class Student {
        private String name;
        private int age;

        /**
         * @param name must not be null or blank
         * @param age  must be 0-120
         */
        Student(String name, int age) {
            setName(name);
            setAge(age);
        }

        /** @param name must not be null or blank */
        public void setName(String name) {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("name cannot be null or blank");
            }
            this.name = name;
        }

        /** @param age must be 0-120 */
        public void setAge(int age) {
            if (age < 0 || age > 120) {
                throw new IllegalArgumentException("age must be 0-120, got " + age);
            }
            this.age = age;
        }

        @Override
        public String toString() {
            return name + " (age " + age + ")";
        }
    }

    /**
     * MET01-J: Never use assertions to validate method arguments.
     * Asserts are off by default, so {@code assert credits > 0;} wouldn't stop anything.
     * Use a regular if-check instead.
     */
    static final class Schedule {
        private static final int MAX_CREDITS = 18;
        private int totalCredits;

        /** @param credits must be positive and keep the total at 18 or less */
        public void enroll(int credits) {
            // written this way so a huge number can't overflow past the check
            if (credits <= 0 || credits > MAX_CREDITS - totalCredits) {
                throw new IllegalArgumentException("invalid credit hours: " + credits);
            }
            totalCredits += credits;
        }

        /** @return total credits enrolled */
        public int getTotalCredits() {
            return totalCredits;
        }
    }

    /**
     * SER01-J: Do not deviate from the proper signatures of serialization methods.
     * writeObject/readObject must be private void, or Java silently ignores them.
     */
    static final class UserProfile implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L; 

        private final String username;
        private transient String password; // transient = not saved

        UserProfile(String username, String password) {
            this.username = username;
            this.password = password;
        }

        /** Correct signature: private void, throws IOException. */
        @Serial
        private void writeObject(ObjectOutputStream out) throws IOException {
            System.out.println("  [SER01-J] custom writeObject() was called");
            out.defaultWriteObject();
        }

        /** Correct signature: private void, throws IOException and ClassNotFoundException. */
        @Serial
        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            System.out.println("  [SER01-J] custom readObject() was called");
            in.defaultReadObject();
            password = ""; // transient field comes back null
        }

        @Override
        public String toString() {
            return "UserProfile[username=" + username + ", password='" + password + "']";
        }
    }

    /**
     * SER04-J: Do not allow serialization and deserialization to bypass the security manager.
     * The same security check used in the constructor and setter also runs in writeObject/readObject.
     */
    static final class Hometown implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;

        private String town = "UNKNOWN";

        public Hometown() {
            securityCheck();
        }

        /** @param newTown must not be null or blank */
        public void changeTown(String newTown) {
            securityCheck();
            town = validate(newTown);
        }

        /** Throws SecurityException if a Security Manager is installed and denies access. */
        private static void securityCheck() {
            SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                sm.checkPermission(new RuntimePermission("changeHometown"));
            }
        }

        /** @return the name if it isn't null or blank */
        private static String validate(String name) {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("town cannot be null or blank");
            }
            return name;
        }

        /** Same security check before writing. */
        @Serial
        private void writeObject(ObjectOutputStream out) throws IOException {
            securityCheck();
            out.defaultWriteObject();
        }

        /** Same security check before reading, then re-check the data. */
        @Serial
        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            securityCheck();
            in.defaultReadObject();
            try {
                validate(town);
            } catch (IllegalArgumentException e) {
                throw new InvalidObjectException(e.getMessage());
            }
        }

        @Override
        public String toString() {
            return town;
        }
    }

    /**
     * SER08-J: Minimize privileges before deserializing from a privileged context.
     * readObject() runs with no permissions. The allow-list filter also blocks
     * unexpected classes, which still works on Java 24+.
     */
    static final class SafeDeserializer {
        private static final AccessControlContext NO_PERMISSIONS = new AccessControlContext(
                new ProtectionDomain[] { new ProtectionDomain(null, new Permissions()) });

        /** Only allow this file's classes; "!*" rejects everything else. */
        private static final ObjectInputFilter ALLOW_LIST =
                ObjectInputFilter.Config.createFilter("TeamProjectDemo$*;!*");

        private SafeDeserializer() {
        }

        /**
         * @param data the serialized bytes
         * @return the deserialized object
         */
        static Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
            try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(data))) {
                in.setObjectInputFilter(ALLOW_LIST);
                return AccessController.doPrivileged(
                        (PrivilegedExceptionAction<Object>) in::readObject, NO_PERMISSIONS);
            } catch (PrivilegedActionException e) {
                // unwrap the real exception
                Exception cause = e.getException();
                if (cause instanceof IOException io) {
                    throw io;
                }
                if (cause instanceof ClassNotFoundException cnf) {
                    throw cnf;
                }
                throw new IOException(cause);
            }
        }
    }

    /**
     * @param obj object to serialize
     * @return the object as bytes
     */
    static byte[] serialize(Serializable obj) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(obj);
        }
        return bytes.toByteArray();
    }
    //End of James' section
    //Start of Jimmy's section
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

    /** Runs a demo for each rule. */
    public static void main(String[] args) throws Exception {
        System.out.println("=== MET00-J: Validate method arguments ===");
        System.out.println("  Created: " + new Student("Reggie", 21));
        try {
            new Student("", -5);
        } catch (IllegalArgumentException e) {
            System.out.println("  Rejected bad input: " + e.getMessage());
        }

        System.out.println("\n=== MET01-J: Never use assertions to validate arguments ===");
        Schedule schedule = new Schedule();
        schedule.enroll(3);
        System.out.println("  Enrolled in 3 credits, total = " + schedule.getTotalCredits());
        try {
            schedule.enroll(-3);
        } catch (IllegalArgumentException e) {
            System.out.println("  Rejected bad input: " + e.getMessage());
        }

        System.out.println("\n=== SER01-J: Proper serialization method signatures ===");
        UserProfile profile = new UserProfile("redbird", "hunter2");
        UserProfile profileCopy = (UserProfile) SafeDeserializer.deserialize(serialize(profile));
        System.out.println("  After round trip: " + profileCopy);

        System.out.println("\n=== SER04-J: Serialization can't bypass security checks ===");
        Hometown home = new Hometown();
        home.changeTown("Normal, IL");
        Hometown homeCopy = (Hometown) SafeDeserializer.deserialize(serialize(home));
        System.out.println("  After round trip: " + homeCopy);

        System.out.println("\n=== SER08-J: Minimize privileges when deserializing ===");
        try {
            SafeDeserializer.deserialize(serialize(new ArrayList<String>()));
        } catch (InvalidClassException e) {
            System.out.println("  Blocked java.util.ArrayList (not on the allow-list)");
        }
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