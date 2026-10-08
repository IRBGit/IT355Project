import java.util.ArrayList;
import java.util.List;

/**
 * OBJ05-J: Do not return references to private mutable class members.
 */
public class Mutable {
    private final List<String> roles = new ArrayList<>();

    public Mutable(String... initialRoles) {
        roles.addAll(List.of(initialRoles));
    }

    public List<String> getRoles() {
        return List.copyOf(roles);
    }

    public static void main(String[] args) {
        Mutable user = new Mutable("reader");
        List<String> returnedRoles = user.getRoles();

        try {
            returnedRoles.add("administrator");
        } catch (UnsupportedOperationException expected) {
            System.out.println("The private list was not exposed.");
        }
    }
}
