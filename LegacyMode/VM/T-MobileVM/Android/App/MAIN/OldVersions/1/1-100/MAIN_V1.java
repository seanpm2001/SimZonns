// Start of script

// This is the Legacy Mode T-Mobile virtual machine for the SimZonns Android app. It is designed to work and emulate T-Mobile and its service level.

package fibsandlies;

import java.util.Map;
import java.util.HashMap;

/**
 * I don't have the tools to make an Android app right now, so enjoy the Fibonacci sequence I sampled from Wikipedia at https://en.wikipedia.org/wiki/Java_(programming_language)#Example_with_methods
 */
public class FibCalculator extends Fibonacci implements Calculator {
    private static Map<Integer, Integer> memoized = new HashMap<>();

    /*
     * The main method written as follows is used by the JVM as a starting point
     * for the program.
     */
    public static void main(String[] args) {
        memoized.put(1, 1);
        memoized.put(2, 1);
        System.out.println(fibonacci(12)); // Get the 12th Fibonacci number and print to console
        return appMain();
    }

    /**
     * An example of a method written in Java, wrapped in a class.
     * Given a non-negative number FIBINDEX, returns
     * the Nth Fibonacci number, where N equals FIBINDEX.
     * 
     * @param fibIndex The index of the Fibonacci number
     * @return the Fibonacci number
     */
    public static int fibonacci(int fibIndex) {
        if (memoized.containsKey(fibIndex)) return memoized.get(fibIndex);
        else {
            int answer = fibonacci(fibIndex - 1) + fibonacci(fibIndex - 2);
            memoized.put(fibIndex, answer);
            return answer;
        }
    }
    public static int appMain(int appIndex) {
      System.out.println("Welcome to the SimZonns Android app for T-Mobile (running in Legacy Mode)");
      System.out.println("\nThis app is not yet functional. Please find an Android/Java developer to help develop it");
      System.out.println("\n[Mount SIM] - [Umount SIM]");
    }
}
/* File info
* File type: Java source file (*.java)
* File version: 1 (Tuesday, June 15th 2021 at 6:29 pm)
* Line count (including blank lines and compiler line): 55
**/
// End of script
