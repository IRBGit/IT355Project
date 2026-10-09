/**
 * OBJ51-J: Minimize the accessibility of classes and their members.
 */
public final class MinimizeAccessibility {
    private final String username;

    private MinimizeAccessibility(String username) {
        this.username = username;
    }

    public static MinimizeAccessibility create(String username) {
        return new MinimizeAccessibility(username);
    }

    public static void main(String[] args) {
        MinimizeAccessibility user = MinimizeAccessibility.create("ian");
        System.out.println("Created user: " + user.username);
    }
}
