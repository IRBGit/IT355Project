import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
/**
 * Compliant examples of five SEI CERT Oracle Java rules:
 *
 * 1. ERR08-J: Do not catch NullPointerException or any of its ancestors
 * 2. FIO02-J: Detect and handle file-related errors
 * 3. EXP02-J: Do not use Object.equals() to compare two arrays
 * 4. OBJ10-J: Do not use public static nonfinal fields
 * 5. EXP00-J: Do not ignore values returned by methods
 *
 * Compile: javac CertRulesCompliant.java
 * Run:     java CertRulesCompliant
 */
public class CertRulesCompliant {

    // Rule 4: OBJ10-J - constants are final; mutable state is private.
    public static final double pi = 3.141;

    // Rule 1: ERR08-J - check for null explicitly instead of catching NPE.
    static boolean isNameMatch(String s, String name) {
        if (s == null) {
            return false;
        }
        return s.equals(name);
    }

    // Rule 2: FIO02-J - use java.nio.file and handle IOException.
    static boolean deleteFile(File file) {
        try{
            Files.delete(file.toPath());;
            return true;
        }
        catch(IOException I){
            return false;
        }
    }

    // Rule 3: EXP02-J - compare array contents, not references.
    static boolean compareArrays(int[] a, int[] b) {
        return Arrays.equals(a, b);
    }

    // Rule 5: EXP00-J - use returned values and check status results.
    static String reverse(String input) {
        String back = "";
        for(int i = input.length(); i > 0; i--){
            back += input.substring(i-1,i);
        }
        return back;
    }

    public static void main(String[] args){
        System.out.println("\n--- Rule 1: ERR08-J ---");
        System.out.println("Comparing names: null and bob:" + isNameMatch(null, "bob"));
        System.out.println("Comparing names: bob and bob:" + isNameMatch("bob", "bob"));

        System.out.println("\n--- Rule 2: FIO02-J ---");
        File myFile = new File(args[0]);
        System.out.println("Created File: " + myFile.getName());
        System.out.println("Deleting File...");
        System.out.println("File deleted?: " + deleteFile(myFile));
        System.out.println("Trying to delete again...");
        System.out.println("File deleted?: " + deleteFile(myFile));

        System.out.println("\n--- Rule 3: EXP02-J ---");
        int[] a = {1, 2, 3};
        int[] b = {1, 2, 3};
        System.out.println("Creating two arrays.");
        System.out.println("Array a: " + Arrays.toString(a));
        System.out.println("Array b: " + Arrays.toString(b));
        System.out.println("Arrays.equals(): " + compareArrays(a, b));

        System.out.println("\n--- Rule 4: OBJ10-J ---");
        int radius = 5;
        System.out.println("A circle with radius 5 has area of: " + (Math.pow(radius,2) * pi));

        System.out.println("\n--- Rule 5: EXP00-J ---");
        String name = "Walter";
        System.out.println("Name: " + name);
        name = reverse(name);
        System.out.println("Reversed name: " + name);
    }
}
