/**
 * IDS16-J: Prevent XML injection.
 *
 * Untrusted text is escaped before it is inserted into XML character data.
 * In larger applications, prefer constructing XML with a DOM or StAX API.
 */
public class Prevent {
    public static void main(String[] args) {
        String userName = "<script>alert('not XML')</script>";
        System.out.println(createGreetingXml(userName));
    }

    public static String createGreetingXml(String userName) {
        return "<greeting><name>"
                + escapeXml(userName)
                + "</name></greeting>";
    }

    private static String escapeXml(String value) {
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }
}
