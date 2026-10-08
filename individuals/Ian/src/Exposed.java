import java.util.Date;

/**
 * OBJ13-J: Prevent references to mutable objects from being exposed.
 */
public class Exposed {
    private final Date createdAt;

    public Exposed(Date createdAt) {
        this.createdAt = new Date(createdAt.getTime());
    }

    public Date getCreatedAt() {
        return new Date(createdAt.getTime());
    }

    public static void main(String[] args) {
        Date originalDate = new Date();
        Exposed record = new Exposed(originalDate);

        originalDate.setTime(0);
        Date returnedDate = record.getCreatedAt();
        returnedDate.setTime(0);

        System.out.println("Stored date remains protected: "
                + (record.getCreatedAt().getTime() != 0));
    }
}
