/**
 * OBJ50-J: Never confuse the immutability of a reference with that of the
 * referenced object.
 */
public class ImmutableReference {
    private final StringBuilder message;

    public ImmutableReference(StringBuilder message) {
        this.message = new StringBuilder(message);
    }

    public String getMessage() {
        return message.toString();
    }

    public static void main(String[] args) {
        StringBuilder original = new StringBuilder("Safe message");
        ImmutableReference record = new ImmutableReference(original);
        original.append(" changed");

        System.out.println("Stored value remains independent: "
                + record.getMessage().equals("Safe message"));
    }
}
