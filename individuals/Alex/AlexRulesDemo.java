package individuals.Alex;

import java.io.*;
import java.lang.reflect.Proxy;
import java.sql.*;
import java.util.*;
import java.util.logging.*;

/**
 * IT355 Group Project 1 - Alex's Rules and Recommendations Demos.
 * Rules: IDS00-J, FIO08-J, SER12-J, EXP03-J, ERR02-J.
 * Recommendations: OBJ51-J, MET52-J, ERR51-J.
 *
 * @author Alex Reyes
 */

public class AlexRulesDemo {
    
    /**
     * IDS00-J: Prevent SQL injection.
     * Use prepared statements to safely handle user input.
     */
    static final class SafeSqlDemo {

        static void findUser(Connection connection, String username)
                throws SQLException {

            String sql = "SELECT id FROM users WHERE username = ?";

            try (PreparedStatement statement =
                    connection.prepareStatement(sql)) {

                statement.setString(1, username);
                statement.execute();
            }
        }
    }

    /**
     * FIO08-J: Distinguish stream data from the end-of-stream value -1.
     * Read into an int before converting any value to a byte or char.
     */
    static final class SafeStreamDemo {
        /**
         * Prints every byte, including FF, without mistaking it for -1.
         *
         * @param bytes sample stream contents
         * @throws IOException if reading fails
         */
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
     * Only allow approved classes to be deserialized.
     */
    static final class SafeDeserializationDemo {

        static final class SafeMessage implements Serializable {
            private static final long serialVersionUID = 1L;
            private final String text;

            SafeMessage(String text) {
                this.text = text;
            }

            String getText() {
                return text;
            }
        }

        static SafeMessage readAllowedMessage(byte[] data)
                throws IOException, ClassNotFoundException {

            try (ObjectInputStream input = new ObjectInputStream(
                    new ByteArrayInputStream(data))) {

                String filter = "maxdepth=4;maxrefs=10;maxbytes=2048;"
                        + SafeMessage.class.getName() + ";!*";

                input.setObjectInputFilter(
                        ObjectInputFilter.Config.createFilter(filter));

                return (SafeMessage) input.readObject();
            }
        }
    }

    /**
     * EXP03-J: Compare the values of boxed primitives, not their references.
     * equals() correctly compares two Integer objects' contents.
     */
    static final class SafeComparisonDemo {
        /**
         * @param first first boxed number
         * @param second second boxed number
         * @return true when both boxed numbers have equal values
         */
        static boolean sameNumber(Integer first, Integer second) {
            return Objects.equals(first, second);
        }
    }

    /**
     * ERR02-J: Prevent exceptions while logging data.
     * Use Java's logging API instead of treating System.err as a logger.
     */
    static final class SafeLoggingDemo {
        private static final Logger LOGGER =
                Logger.getLogger(SafeLoggingDemo.class.getName());

        /** Records a security error through a real Logger. */
        static void demonstrate() {
            try {
                throw new SecurityException("Access denied");
            } catch (SecurityException exception) {
                LOGGER.log(Level.WARNING,
                        "[ERR02-J] An unauthorized action was blocked", exception);
            }
        }
    }

    /**
     * OBJ51-J: Minimize access to classes and their members.
     * The internal account class and its data are not publicly accessible.
     */
    static final class PrivateAccount {
        private int balance;

        /** @param startingBalance opening amount */
        private PrivateAccount(int startingBalance) {
            balance = startingBalance;
        }

        /** @param amount amount to deposit */
        private void deposit(int amount) {
            if (amount < 0) {
                throw new IllegalArgumentException("Deposit cannot be negative");
            }
            balance += amount;
        }

        /** @return current account balance */
        private int getBalance() {
            return balance;
        }
    }

    /**
     * MET52-J: Do not clone untrusted method parameters.
     * Make a copy using a trusted constructor instead of input.clone().
     */
    static final class SafeDateStore {
        private final Date savedDate;

        /** @param input a potentially untrusted mutable Date object */
        SafeDateStore(Date input) {
            savedDate = new Date(Objects.requireNonNull(input).getTime());
        }

        /** @return a timestamp that is not affected by changes to input */
        long getTime() {
            return savedDate.getTime();
        }
    }

    /**
     * ERR51-J: Prefer specific user-defined exception types.
     * Callers can catch InvalidScoreException instead of a broad Exception.
     */
    static final class ScoreValidator {
        /** Exception for an invalid score. */
        static final class InvalidScoreException extends Exception {
            private static final long serialVersionUID = 1L;

            /** @param message description of the invalid score */
            InvalidScoreException(String message) {
                super(message);
            }
        }

        /**
         * @param score the number to check
         * @throws InvalidScoreException when the score is outside 0 through 100
         */
        static void checkScore(int score) throws InvalidScoreException {
            if (score < 0 || score > 100) {
                throw new InvalidScoreException("Score must be between 0 and 100");
            }
        }
    }

    /**
     * Runs every assigned rule and the three unclaimed recommendations.
     *
     * @param args unused command-line arguments
     * @throws Exception if an unexpected demo error occurs
     */
    public static void main(String[] args) throws Exception {
        System.out.println("=== IDS00-J: Prepared statement ===");
        try (Connection connection = SafeSqlDemo.demoConnection()) {
            SafeSqlDemo.findUser(connection, "alex' OR '1'='1");
        }

        System.out.println("\n=== FIO08-J: End-of-stream check ===");
        SafeStreamDemo.readBytes(new byte[] { 0x41, (byte) 0xFF, 0x42 });

        System.out.println("\n=== SER12-J: Allowlisted deserialization ===");
        byte[] allowed = SafeDeserializationDemo.makeSampleBytes(
                new SafeDeserializationDemo.SafeMessage("Safe data"));
        System.out.println("  [SER12-J] Allowed: "
                + SafeDeserializationDemo.readAllowedMessage(allowed).getText());
        byte[] disallowed = SafeDeserializationDemo.makeSampleBytes(new Date(0L));
        try {
            SafeDeserializationDemo.readAllowedMessage(disallowed);
            throw new AssertionError("Disallowed object was not blocked");
        } catch (InvalidClassException expected) {
            System.out.println("  [SER12-J] Blocked an untrusted class");
        }

        System.out.println("\n=== EXP03-J: Compare boxed values ===");
        Integer first = Integer.valueOf(1000);
        Integer second = Integer.valueOf(1000);
        System.out.println("  [EXP03-J] Same numerical value: "
                + SafeComparisonDemo.sameNumber(first, second));

        System.out.println("\n=== ERR02-J: Reliable error logging ===");
        SafeLoggingDemo.demonstrate();

        System.out.println("\n=== OBJ51-J: Private members ===");
        PrivateAccount account = new PrivateAccount(50);
        account.deposit(25);
        System.out.println("  [OBJ51-J] Updated through internal method: "
                + account.getBalance());

        System.out.println("\n=== MET52-J: Trusted defensive copy ===");
        Date original = new Date(5000L);
        SafeDateStore store = new SafeDateStore(original);
        original.setTime(9999L);
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
