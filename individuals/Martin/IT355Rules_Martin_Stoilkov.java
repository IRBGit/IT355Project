import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;

/**

 * 1. ERR08-J: Do not catch NullPointerException or any of its ancestors
 * 2. FIO02-J: Detect and handle file-related errors
 * 3. EXP02-J: Do not use Object.equals() to compare two arrays
 * 4. OBJ10-J: Do not use public static nonfinal fields
 * 5. EXP00-J: Do not ignore values returned by methods
 *
 */
public class IT355Rules_Martin_Stoilkov {

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

    // Rule 5: EXP00-J - use method return values.
    static String reverse(String input) {
        String back = "";
        for(int i = input.length(); i > 0; i--){
            back += input.substring(i-1,i);
        }
        return back;
    }

    /**
     * Returns the sum of the squares of the given numbers.
     *
     * MET51-J: a single method handles Integer, Double, Long, etc.
     *          through Number's polymorphic doubleValue(), instead of
     *          overloads that the compiler picks from the static type.
     * OBJ54-J: 'squares' is left to go out of scope; it is not nulled.
     */
    static double sumOfSquares(List<? extends Number> numbers) {
        List<Double> squares = new ArrayList<>();
        for (Number n : numbers) {
            double value = n.doubleValue();
            squares.add(value * value);
        }

        double total = 0;
        for (double sq : squares) {
            total += sq;
        }
        return total;
    }


    // ERR50-J: use normal control flow for expected situations.
    // Iterate with a for-each loop instead of looping until an
    // ArrayIndexOutOfBoundsException is thrown.
    static int sum(int[] values) {
        int total = 0;
        for (int v : values) {
            total += v;
        }
        return total;
    }

    public static void main(String[] args){
        System.out.println("\n--- Rule 1: ERR08-J ---");
        System.out.println("Comparing names: null and bob:" + isNameMatch(null, "bob"));
        System.out.println("Comparing names: bob and bob:" + isNameMatch("bob", "bob"));

        System.out.println("\n--- Rule 2: FIO02-J ---");
        File myFile = new File("Example.txt");
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

        System.out.println("\n--- Recommendations 1 and 3: MET51-J, OBJ54-J ---");
        System.out.println("Integers: " + sumOfSquares(List.of(1, 2, 3)));
        System.out.println("Doubles:  " + sumOfSquares(List.of(1.5, 2.5, 3.5)));

        System.out.println("\n--- Recommendation 2: ERR50-J ---");
        System.out.println("Sum of array a: "+ sum(a));
    }
}
