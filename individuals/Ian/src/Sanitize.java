import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * IDS07-J: Sanitize untrusted data passed to Runtime.exec().
 *
 * The command is selected from an allowlist and the arguments are passed
 * separately. This avoids letting user input become part of a shell command.
 */
public class Sanitize {
    private static final Map<String, List<String>> ALLOWED_COMMANDS = Map.of(
            "list", List.of("java", "-version")
    );

    public static void main(String[] args) throws IOException, InterruptedException {
        runAllowedCommand("list");
    }

    public static int runAllowedCommand(String commandName)
            throws IOException, InterruptedException {
        List<String> command = ALLOWED_COMMANDS.get(commandName);
        if (command == null) {
            throw new IllegalArgumentException("Unsupported command");
        }

        Process process = new ProcessBuilder(command)
                .redirectErrorStream(true)
                .inheritIO()
                .start();
        return process.waitFor();
    }
}
