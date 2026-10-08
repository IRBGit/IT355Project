import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * IT355 Group Project 1 - comprehensive security rule demos.
 * Note: Java 24+ turns off the Security Manager, so its checks below don't do anything there.
 *
 * @author James, Ian, Martin, & Jimmy
 */
@SuppressWarnings("removal") // SecurityManager is deprecated
public class TeamProjectDemo {
    // START OF JAMES' SECTION
    
    /**
     * MET00-J: Validate method arguments[cite: 6].
     */
    static final class Student {
        private String name;
        private int age;

        Student(String name, int age) {
            setName(name);
            setAge(age);
        }

        public void setName(String name) {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("name cannot be null or blank");
            }
            this.name = name;
        }

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
     * MET01-J: Never use assertions to validate method arguments[cite: 6].
     */
    static final class Schedule {
        private static final int MAX_CREDITS = 18;
        private int totalCredits;

        public void enroll(int credits) {
            if (credits <= 0 || credits > MAX_CREDITS - totalCredits) {
                throw new IllegalArgumentException("invalid credit hours: " + credits);
            }
            totalCredits += credits;
        }

        public int getTotalCredits() {
            return totalCredits;
        }
    }

    /**
     * SER01-J: Do not deviate from proper signatures of serialization methods[cite: 6].
     */
    static final class UserProfile implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L; 

        private final String username;
        private transient String password;

        UserProfile(String username, String password) {
            this.username = username;
            this.password = password;
        }

        @Serial
        private void writeObject(ObjectOutputStream out) throws IOException {
            System.out.println("  [SER01-J] custom writeObject() was called");
            out.defaultWriteObject();
        }

        @Serial
        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            System.out.println("  [SER01-J] custom readObject() was called");
            in.defaultReadObject();
            password = ""; 
        }

        @Override
        public String toString() {
            return "UserProfile[username=" + username + ", password='" + password + "']";
        }
    }

    /**
     * SER04-J: Do not allow serialization to bypass the security manager[cite: 6].
     */
    static final class Hometown implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;

        private String town = "UNKNOWN";

        public Hometown() {
            securityCheck();
        }

        public void changeTown(String newTown) {
            securityCheck();
            town = validate(newTown);
        }

        private static void securityCheck() {
            SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                sm.checkPermission(new RuntimePermission("changeHometown"));
            }
        }

        private static String validate(String name) {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("town cannot be null or blank");
            }
            return name;
        }

        @Serial
        private void writeObject(ObjectOutputStream out) throws IOException {
            securityCheck();
            out.defaultWriteObject();
        }

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
     * SER08-J: Minimize privileges before deserializing from a privileged context[cite: 6].
     */
    static final class SafeDeserializer {
        private static final AccessControlContext NO_PERMISSIONS = new AccessControlContext(
                new ProtectionDomain[] { new ProtectionDomain(null, new Permissions()) });

        private static final ObjectInputFilter ALLOW_LIST =
                ObjectInputFilter.Config.createFilter("TeamProjectDemo$*;!*");

        private SafeDeserializer() {
        }

        static Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
            try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(data))) {
                in.setObjectInputFilter(ALLOW_LIST);
                return AccessController.doPrivileged(
                        (PrivilegedExceptionAction<Object>) in::readObject, NO_PERMISSIONS);
            } catch (PrivilegedActionException e) {
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

    static byte[] serialize(Serializable obj) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(obj);
        }
        return bytes.toByteArray();
    }

    // START OF JIMMY'S SECTION

    /**
     * MET50-J: Avoid ambiguous or confusing uses of overloading[cite: 6].
     */
    static final class Calculator {
        public void printValue(int x) {
            System.out.println("  [MET50-J] Processing integer: " + x);
        }

        public void printValue(String text) {
            System.out.println("  [MET50-J] Processing string: " + text);
        }
    }

    /**
     * MET53-J: Ensure that the clone() method calls super.clone()[cite: 6].
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
     * ERR54-J: Use a try-with-resources statement to safely handle closeable resources[cite: 6].
     */
    static final class FileReaderUtil {
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
     * SER05-J: Do not serialize instances of inner classes[cite: 6].
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
     * MET06-J: Do not invoke overridable methods in clone()[cite: 6].
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
     * MET12-J: Do not use finalizers[cite: 6].
     */
    static final class ExplicitResource implements AutoCloseable {
        @Override
        public void close() {
            System.out.println("  [MET12-J] Explicitly cleaned up resource (no finalizer)");
        }
    }

    /**
     * MET05-J: Ensure that constructors do not call overridable methods[cite: 6].
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
     * ERR01-J: Do not allow exceptions to expose sensitive information[cite: 6].
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

    // START OF IAN'S SECTION

    /**
     * OBJ11-J: Ensure that constructors do not throw exceptions[cite: 1].
     */
    static final class SafeConstructorRecord {
        private final String contents;

        private SafeConstructorRecord(String contents) {
            this.contents = contents;
        }

        public static Optional<SafeConstructorRecord> fromFile(Path path) {
            try {
                return Optional.of(new SafeConstructorRecord(Files.readString(path)));
            } catch (IOException exception) {
                return Optional.empty();
            }
        }

        public String getContents() {
            return contents;
        }
    }

    /**
     * OBJ13-J: Prevent references to mutable objects from being exposed[cite: 2].
     */
    static final class ExposedRecord {
        private final Date createdAt;

        public ExposedRecord(Date createdAt) {
            this.createdAt = new Date(createdAt.getTime());
        }

        public Date getCreatedAt() {
            return new Date(createdAt.getTime());
        }
    }

    /**
     * OBJ05-J: Do not return references to private mutable class members[cite: 3].
     */
    static final class MutableRoles {
        private final List<String> roles = new ArrayList<>();

        public MutableRoles(String... initialRoles) {
            roles.addAll(List.of(initialRoles));
        }

        public List<String> getRoles() {
            return List.copyOf(roles);
        }
    }

    /**
     * IDS16-J: Prevent XML injection[cite: 4].
     */
    static final class XmlEscaper {
        public static String createGreetingXml(String userName) {
            return "<greeting><name>"
                    + escapeXml(userName)
                    + "</name></greeting>";
        }

        private static String escapeXml(String value) {
            return value
                    .replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
                    .replace("'", "&apos;");
        }
    }

    /**
     * IDS07-J: Sanitize untrusted data passed to Runtime.exec()[cite: 5].
     */
    static final class CommandSanitizer {
        private static final Map<String, List<String>> ALLOWED_COMMANDS = Map.of(
                "list", List.of("java", "-version")
        );

        public static int runAllowedCommand(String commandName)
                throws IOException, InterruptedException {
            List<String> command = ALLOWED_COMMANDS.get(commandName);
            if (command == null) {
                throw new IllegalArgumentException("Unsupported command");
            }

            Process process = new ProcessBuilder(command)
                    .redirectErrorStream(true)
                    .start();
            return process.waitFor();
        }
    }

    // START OF MARTIN'S SECTION
    

    /**
     * OBJ10-J: Do not use public static nonfinal fields.
     */
    public static final double PI_CONSTANT = 3.141;

    /**
     * ERR08-J: Do not catch NullPointerException or any of its ancestors.
     */
    static final class NullCheckUtil {
        public static boolean isNameMatch(String s, String name) {
            if (s == null) {
                return false;
            }
            return s.equals(name);
        }
    }

    /**
     * FIO02-J: Detect and handle file-related errors.
     */
    static final class FileHandlerUtil {
        public static boolean deleteFile(File file) {
            try {
                Files.delete(file.toPath());
                return true;
            } catch (IOException e) {
                return false;
            }
        }
    }

    /**
     * EXP02-J: Do not use Object.equals() to compare two arrays.
     */
    static final class ArrayCompareUtil {
        public static boolean compareArrays(int[] a, int[] b) {
            return Arrays.equals(a, b);
        }
    }

    /**
     * EXP00-J: Do not ignore values returned by methods.
     */
    static final class StringReverseUtil {
        public static String reverse(String input) {
            String back = "";
            for (int i = input.length(); i > 0; i--) {
                back += input.substring(i - 1, i);
            }
            return back;
        }
    }

    // MAIN EXECUTION METHOD
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

        System.out.println("\n=== MET50-J: Distinct overloads ===");
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

        System.out.println("\n=== OBJ11-J: Constructor exception avoidance ===");
        SafeConstructorRecord.fromFile(Path.of("example.txt"))
                .ifPresentOrElse(
                        file -> System.out.println("  Read file contents successfully"),
                        () -> System.out.println("  [OBJ11-J] Handled missing file via Optional safely")
                );

        System.out.println("\n=== OBJ13-J: Prevent mutable date reference exposure ===");
        Date originalDate = new Date();
        ExposedRecord record = new ExposedRecord(originalDate);
        originalDate.setTime(0);
        System.out.println("  [OBJ13-J] Stored date remains protected: "
                + (record.getCreatedAt().getTime() != 0));

        System.out.println("\n=== OBJ05-J: Protect private mutable lists ===");
        MutableRoles userRoles = new MutableRoles("reader");
        List<String> returnedRoles = userRoles.getRoles();
        try {
            returnedRoles.add("administrator");
        } catch (UnsupportedOperationException expected) {
            System.out.println("  [OBJ05-J] The private list was protected from modification");
        }

        System.out.println("\n=== IDS16-J: Prevent XML injection ===");
        String unsafeUser = "<script>alert('test')</script>";
        System.out.println("  [IDS16-J] Escaped XML: " + XmlEscaper.createGreetingXml(unsafeUser));

        System.out.println("\n=== IDS07-J: Sanitize Runtime.exec() input ===");
        int exitCode = CommandSanitizer.runAllowedCommand("list");
        System.out.println("  [IDS07-J] Allowed command exited with code: " + exitCode);

        // --- Martin's Rules Execution ---
        System.out.println("\n=== ERR08-J: Explicit null check instead of catching NPE ===");
        System.out.println("  Comparing null and bob: " + NullCheckUtil.isNameMatch(null, "bob"));
        System.out.println("  Comparing bob and bob: " + NullCheckUtil.isNameMatch("bob", "bob"));

        System.out.println("\n=== FIO02-J: Detect and handle file errors safely ===");
        File tempTestFile = File.createTempFile("cert-test", ".tmp");
        System.out.println("  Created Temp File: " + tempTestFile.getName());
        System.out.println("  File deleted successfully?: " + FileHandlerUtil.deleteFile(tempTestFile));
        System.out.println("  Trying to delete again: " + FileHandlerUtil.deleteFile(tempTestFile));

        System.out.println("\n=== EXP02-J: Array content comparison ===");
        int[] arrA = {1, 2, 3};
        int[] arrB = {1, 2, 3};
        System.out.println("  Arrays.equals(): " + ArrayCompareUtil.compareArrays(arrA, arrB));

        System.out.println("\n=== OBJ10-J: Immutable public static final constants ===");
        double radius = 5.0;
        System.out.println("  Circle area with radius 5: " + (Math.pow(radius, 2) * PI_CONSTANT));

        System.out.println("\n=== EXP00-J: Utilizing method return values ===");
        String originalName = "Walter";
        String reversedName = StringReverseUtil.reverse(originalName);
        System.out.println("  Original: " + originalName + ", Reversed: " + reversedName);
    }
}