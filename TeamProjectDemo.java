import java.io.*;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.sql.*;
import java.util.*;
import java.util.Date;
import java.util.logging.*;

/**
 * IT355 Group Project 1 - comprehensive security rule and recommendation demos.
 * Note: Java 24+ turns off the Security Manager, so its checks below don't do anything there.
 *
 * @author James Strickert, Ian, Martin, Jimmy, & Alex
 */
@SuppressWarnings("removal") // SecurityManager is deprecated
public class TeamProjectDemo {
    // ------------------------------------------
    // START OF JAMES' SECTION
    // ------------------------------------------
    
    /**
     * MET00-J: Validate method arguments.
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
     * MET01-J: Never use assertions to validate method arguments.
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
     * SER01-J: Do not deviate from proper signatures of serialization methods.
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
     * SER04-J: Do not allow serialization to bypass the security manager.
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
     * SER08-J: Minimize privileges before deserializing from a privileged context.
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

    // ------------------------------------------
    // START OF JIMMY'S SECTION
    // ------------------------------------------

    /**
     * MET50-J: Avoid ambiguous or confusing uses of overloading.
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
     * MET53-J: Ensure that the clone() method calls super.clone().
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
     * SER05-J: Do not serialize instances of inner classes.
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
     */
    static final class ExplicitResource implements AutoCloseable {
        @Override
        public void close() {
            System.out.println("  [MET12-J] Explicitly cleaned up resource (no finalizer)");
        }
    }

    /**
     * MET05-J: Ensure that constructors do not call overridable methods.
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

    // ------------------------------------------
    // START OF IAN'S SECTION
    // ------------------------------------------

    /**
     * OBJ11-J: Ensure that constructors do not throw exceptions.
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
     * OBJ13-J: Prevent references to mutable objects from being exposed.
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
     * OBJ05-J: Do not return references to private mutable class members.
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
     * IDS16-J: Prevent XML injection.
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
     * IDS07-J: Sanitize untrusted data passed to Runtime.exec().
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

    // ------------------------------------------
    // START OF MARTIN'S SECTION
    // ------------------------------------------

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

    // ------------------------------------------
    // START OF ALEX'S SECTION
    // ------------------------------------------

    /**
     * IDS00-J: Prevent SQL injection.
     */
    static final class SafeSqlDemo {
        static void findUser(Connection connection, String username) throws SQLException {
            String sql = "SELECT id FROM users WHERE username = ?";
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, username);
                statement.execute();
                System.out.println("  [IDS00-J] Prepared statement executed safely for: " + username);
            }
        }

        static Connection createDummyConnection() {
            return (Connection) Proxy.newProxyInstance(
                    Connection.class.getClassLoader(),
                    new Class<?>[]{Connection.class},
                    (proxy, method, args) -> {
                        if (method.getName().equals("prepareStatement")) {
                            return Proxy.newProxyInstance(
                                    PreparedStatement.class.getClassLoader(),
                                    new Class<?>[]{PreparedStatement.class},
                                    (pProxy, pMethod, pArgs) -> {
                                        if (pMethod.getName().equals("execute")) return true;
                                        if (pMethod.getName().equals("close")) return null;
                                        return null;
                                    }
                            );
                        }
                        if (method.getName().equals("close")) return null;
                        return null;
                    }
            );
        }
    }

    /**
     * FIO08-J: Distinguish stream data from the end-of-stream value -1.
     */
    static final class SafeStreamDemo {
        static void readBytes(byte[] bytes) throws IOException {
            try (InputStream input = new ByteArrayInputStream(bytes)) {
                int value;
                StringBuilder result = new StringBuilder();
                while ((value = input.read()) != -1) {
                    result.append(String.format("%02X ", value));
                }
                System.out.println("  [FIO08-J] All bytes read: " + result.toString().trim());
            }
        }
    }

    /**
     * SER12-J: Prevent deserialization of untrusted data.
     */
    static final class SafeDeserializationDemo {
        static final class SafeMessage implements Serializable {
            @Serial
            private static final long serialVersionUID = 1L;
            private final String text;

            SafeMessage(String text) {
                this.text = text;
            }

            String getText() {
                return text;
            }
        }

        static SafeMessage readAllowedMessage(byte[] data) throws IOException, ClassNotFoundException {
            try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(data))) {
                String filter = "maxdepth=4;maxrefs=10;maxbytes=2048;"
                        + SafeMessage.class.getName() + ";!*";
                input.setObjectInputFilter(ObjectInputFilter.Config.createFilter(filter));
                return (SafeMessage) input.readObject();
            }
        }
    }

    /**
     * EXP03-J: Compare the values of boxed primitives, not their references.
     */
    static final class SafeComparisonDemo {
        static boolean sameNumber(Integer first, Integer second) {
            return Objects.equals(first, second);
        }
    }

    /**
     * ERR02-J: Prevent exceptions while logging data.
     */
    static final class SafeLoggingDemo {
        private static final Logger LOGGER = Logger.getLogger(SafeLoggingDemo.class.getName());

        static void demonstrate() {
            try {
                throw new SecurityException("Access denied");
            } catch (SecurityException exception) {
                LOGGER.log(Level.WARNING, "[ERR02-J] An unauthorized action was blocked", exception);
            }
        }
    }

    /**
     * OBJ51-J: Minimize access to classes and their members.
     */
    static final class PrivateAccount {
        private int balance;

        PrivateAccount(int startingBalance) {
            balance = startingBalance;
        }

        void deposit(int amount) {
            if (amount < 0) {
                throw new IllegalArgumentException("Deposit cannot be negative");
            }
            balance += amount;
        }

        int getBalance() {
            return balance;
        }
    }

    /**
     * MET52-J: Do not clone untrusted method parameters.
     */
    static final class SafeDateStore {
        private final Date savedDate;

        SafeDateStore(Date input) {
            savedDate = new Date(Objects.requireNonNull(input).getTime());
        }

        long getTime() {
            return savedDate.getTime();
        }
    }

    /**
     * ERR51-J: Prefer specific user-defined exception types.
     */
    static final class ScoreValidator {
        static final class InvalidScoreException extends Exception {
            @Serial
            private static final long serialVersionUID = 1L;

            InvalidScoreException(String message) {
                super(message);
            }
        }

        static void checkScore(int score) throws InvalidScoreException {
            if (score < 0 || score > 100) {
                throw new InvalidScoreException("Score must be between 0 and 100");
            }
        }
    }

    // ------------------------------------------
    // MAIN EXECUTION METHOD
    // ------------------------------------------
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

        // --- Alex's Rules & Recommendations Execution ---
        System.out.println("\n=== IDS00-J: Prepared statement ===");
        try (Connection connection = SafeSqlDemo.createDummyConnection()) {
            SafeSqlDemo.findUser(connection, "alex' OR '1'='1");
        }

        System.out.println("\n=== FIO08-J: End-of-stream check ===");
        SafeStreamDemo.readBytes(new byte[] { 0x41, (byte) 0xFF, 0x42 });

        System.out.println("\n=== SER12-J: Allowlisted deserialization ===");
        byte[] allowed = serialize(new SafeDeserializationDemo.SafeMessage("Safe data"));
        System.out.println("  [SER12-J] Allowed: "
                + SafeDeserializationDemo.readAllowedMessage(allowed).getText());
        byte[] disallowed = serialize(new Date(0L));
        try {
            SafeDeserializationDemo.readAllowedMessage(disallowed);
            throw new AssertionError("Disallowed object was not blocked");
        } catch (InvalidClassException expected) {
            System.out.println("  [SER12-J] Blocked an untrusted class");
        }

        System.out.println("\n=== EXP03-J: Compare boxed values ===");
        Integer firstInt = Integer.valueOf(1000);
        Integer secondInt = Integer.valueOf(1000);
        System.out.println("  [EXP03-J] Same numerical value: "
                + SafeComparisonDemo.sameNumber(firstInt, secondInt));

        System.out.println("\n=== ERR02-J: Reliable error logging ===");
        SafeLoggingDemo.demonstrate();

        System.out.println("\n=== OBJ51-J: Private members ===");
        PrivateAccount acc = new PrivateAccount(50);
        acc.deposit(25);
        System.out.println("  [OBJ51-J] Updated through internal method: "
                + acc.getBalance());

        System.out.println("\n=== MET52-J: Trusted defensive copy ===");
        Date origDate = new Date(5000L);
        SafeDateStore store = new SafeDateStore(origDate);
        origDate.setTime(9999L);
        System.out.println("  [MET52-J] Stored time stays at: " + store.getTime());

        System.out.println("\n=== ERR51-J: Specific exception type ===");
        try {
            ScoreValidator.checkScore(150);
        } catch (ScoreValidator.InvalidScoreException expected) {
            System.out.println("  [ERR51-J] Caught expected error: "
                    + expected.getMessage());
        }
    }
}