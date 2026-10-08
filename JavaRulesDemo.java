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
public class JavaRulesDemo {

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
                ObjectInputFilter.Config.createFilter("JavaRulesDemo$*;!*");

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
    }
}
