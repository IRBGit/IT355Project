/**
 * MET53-J: Ensure that the clone() method calls super.clone().
 *
 * Calling super.clone() preserves the object's runtime type and performs
 * the standard field-by-field copy.
 */
public class ProperClone implements Cloneable {
    private final String name;

    public ProperClone(String name) {
        this.name = name;
    }

    @Override
    public ProperClone clone() {
        try {
            return (ProperClone) super.clone();
        } catch (CloneNotSupportedException exception) {
            throw new AssertionError(exception);
        }
    }

    public String getName() {
        return name;
    }

    public static void main(String[] args) {
        ProperClone original = new ProperClone("example");
        ProperClone copy = original.clone();
        System.out.println("Cloned object: " + copy.getName());
    }
}
