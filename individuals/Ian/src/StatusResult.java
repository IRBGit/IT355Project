/**
 * ERR52-J: Avoid in-band error indicators.
 *
 * Success and failure are represented by the result type rather than by a
 * special value such as -1 or null.
 */
public class StatusResult {
    private final String value;
    private final String error;

    private StatusResult(String value, String error) {
        this.value = value;
        this.error = error;
    }

    public static StatusResult success(String value) {
        return new StatusResult(value, null);
    }

    public static StatusResult failure(String error) {
        return new StatusResult(null, error);
    }

    public boolean isSuccess() {
        return error == null;
    }

    public String getValue() {
        return value;
    }

    public String getError() {
        return error;
    }

    public static void main(String[] args) {
        StatusResult result = StatusResult.failure("Username is unavailable");
        if (result.isSuccess()) {
            System.out.println("Created username: " + result.getValue());
        } else {
            System.out.println("Request failed: " + result.getError());
        }
    }
}
