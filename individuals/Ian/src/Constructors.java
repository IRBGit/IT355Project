import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/**
 * OBJ11-J: Ensure that constructors do not throw exceptions.
 *
 * The constructor only receives already-validated data. Operations that can
 * fail use a factory method and report failure with Optional.
 */
public class Constructors {
    private final String contents;

    private Constructors(String contents) {
        this.contents = contents;
    }

    public static Optional<Constructors> fromFile(Path path) {
        try {
            return Optional.of(new Constructors(Files.readString(path)));
        } catch (IOException exception) {
            return Optional.empty();
        }
    }

    public String getContents() {
        return contents;
    }

    public static void main(String[] args) {
        fromFile(Path.of("example.txt"))
                .ifPresentOrElse(
                        file -> System.out.println(file.getContents()),
                        () -> System.out.println("The file could not be read.")
                );
    }
}
