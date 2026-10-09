/**
 * ERR51-J: Prefer user-defined exceptions over more general exception types.
 */
public class UserDefinedException {
    private static class InvalidAgeException extends Exception {
        InvalidAgeException(String message) {
            super(message);
        }
    }

    private static void registerUser(int age) throws InvalidAgeException {
        if (age < 18) {
            throw new InvalidAgeException("User must be at least 18 years old");
        }
    }

    public static void main(String[] args) {
        try {
            registerUser(16);
        } catch (InvalidAgeException exception) {
            System.out.println("Registration rejected: " + exception.getMessage());
        }
    }
}
