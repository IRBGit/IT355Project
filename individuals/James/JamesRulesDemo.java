import java.io.*;
import java.security.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * IT355 Group Project 1 - demos for rules MET00-J, MET01-J, SER01-J, SER04-J, and SER08-J,
 * and recommendations OBJ58-J, MET54-J, and MET55-J.
 * Note: Java 24+ turns off the Security Manager, so its checks below don't do anything there.
 *
 * @author James Strickert
 */
@SuppressWarnings("removal") // SecurityManager is deprecated
public class JamesRulesDemo {

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
     * OBJ58-J: Limit the extensibility of classes and methods with invariants.
     * The invariant: a Course never changes after it's created. The class is final and its
     * fields are private final, so no subclass can override getCredits() to return a different
     * number later. For example, {@code class FakeCourse extends Course} won't compile.
     */
    static final class Course {
        private final String code;
        private final int credits;

        /**
         * @param code    course code like "IT355", must not be null or blank
         * @param credits credit hours, must be positive
         * @throws IllegalArgumentException if either value is invalid
         */
        Course(String code, int credits) {
            if (code == null || code.isBlank()) {
                throw new IllegalArgumentException("course code cannot be null or blank");
            }
            if (credits <= 0) {
                throw new IllegalArgumentException("credits must be positive, got " + credits);
            }
            this.code = code;
            this.credits = credits;
        }

        /** @return the course code */
        public String getCode() {
            return code;
        }

        /** @return the credit hours */
        public int getCredits() {
            return credits;
        }

        @Override
        public String toString() {
            return code + " (" + credits + " cr)";
        }
    }

    /**
     * MET01-J: Never use assertions to validate method arguments.
     * Asserts are off by default, so {@code assert course != null;} wouldn't stop anything.
     * Use a regular if-check instead.
     * <p>
     * MET54-J: enroll() returns the new total so the caller knows it worked.
     * MET55-J: getCourses() returns an empty list, never null.
     */
    static final class Schedule {
        private static final int MAX_CREDITS = 18;
        private final List<Course> courses = new ArrayList<>();
        private int totalCredits;

        /**
         * MET54-J: returns the new total instead of void, and throws if it fails,
         * so the caller always finds out what happened.
         *
         * @param course the course to add, must not be null or push the total over 18
         * @return the new total credits after enrolling
         * @throws IllegalArgumentException if the course is null or would go over 18 credits
         */
        public int enroll(Course course) {
            if (course == null) {
                throw new IllegalArgumentException("course cannot be null");
            }
            // written this way so a huge number can't overflow past the check
            if (course.getCredits() > MAX_CREDITS - totalCredits) {
                throw new IllegalArgumentException(
                        "can't add " + course + ", limit is " + MAX_CREDITS + " credits");
            }
            courses.add(course);
            totalCredits += course.getCredits();
            return totalCredits;
        }

        /** @return total credits enrolled */
        public int getTotalCredits() {
            return totalCredits;
        }

        /**
         * MET55-J: returns an empty list instead of null when nothing is enrolled.
         * The list is read-only, and Course is immutable (OBJ58-J), so callers can't
         * change the schedule behind its back.
         *
         * @return the enrolled courses, or an empty list if there are none
         */
        public List<Course> getCourses() {
            if (courses.isEmpty()) {
                return Collections.emptyList(); // never return null
            }
            return Collections.unmodifiableList(courses);
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
        try {
            schedule.enroll(new Course("IT999", 19));
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

        System.out.println("\n=== OBJ58-J: Limit extensibility of classes with invariants ===");
        Course it355 = new Course("IT355", 3);
        boolean isFinal = java.lang.reflect.Modifier.isFinal(Course.class.getModifiers());
        System.out.println("  " + it355 + " -> Course is final: " + isFinal
                + ", so no subclass can change its credits");

        System.out.println("\n=== MET54-J: Always provide feedback about the result ===");
        System.out.println("  enroll() returned new total = " + schedule.enroll(it355));
        System.out.println("  enroll() returned new total = " + schedule.enroll(new Course("IT326", 3)));

        System.out.println("\n=== MET55-J: Return an empty collection instead of null ===");
        List<Course> none = new Schedule().getCourses();
        System.out.println("  New schedule has " + none.size() + " courses (no null check needed)");
        for (Course c : schedule.getCourses()) {
            System.out.println("  Enrolled: " + c);
        }
    }
}
