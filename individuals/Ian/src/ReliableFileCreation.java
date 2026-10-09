import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * FIO50-J: Do not make assumptions about file creation.
 */
public class ReliableFileCreation {
    public static void main(String[] args) {
        Path file = Path.of("example-output.txt");

        try {
            Files.createFile(file);
            System.out.println("Created new file: " + file);
        } catch (FileAlreadyExistsException exception) {
            System.out.println("File already exists: " + file);
        } catch (IOException exception) {
            System.err.println("Could not create file: " + exception.getMessage());
        }
    }
}
