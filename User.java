package IT355Project;
/* Compliant Solution SER05: needs summary and non compliant example*/
import java.io.*;
public class User implements Serializable {
    private int age;
    private String name;
    static class InnerUser implements Serializable{
        protected String password;
    }

public static void main(String[] args) throws IOException, ClassNotFoundException {
    User user = new User();
    user.age = 22;
    user.name = "Jimmy";
    User.InnerUser member = new User.InnerUser();    
    member.password = "abc123";
    FileOutputStream fileOut = new FileOutputStream("UserInfo.ser");
    ObjectOutputStream out = new ObjectOutputStream(fileOut);
    out.writeObject(user);
    out.writeObject(member);
    out.close();
    fileOut.close();

    System.out.println("object info saved");
    user = null;
    member = null;
    FileInputStream fileIn = new FileInputStream("UserInfo.ser");
    ObjectInputStream in = new ObjectInputStream(fileIn);
    user = (User) in.readObject();
    member = (User.InnerUser) in.readObject();
    in.close();
    fileIn.close();
    System.out.println(user.name);
    System.out.println(user.age);
    System.out.println(member.password);

}
}