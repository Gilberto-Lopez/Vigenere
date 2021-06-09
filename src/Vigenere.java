/** Vigenere encryption scheme cryptanalysis utilities. */
public class Vigenere {

    /** Letter frequencies in the Spanish language (as probabilities). */
    public static double[] p = {
            0.12027,0.02215,0.04019,0.05010,0.12614,0.00692,0.01768,  // A - G
            0.00703,0.06972,0.00493,0.00011,0.04967,0.03157,0.06712,  // H - N
            0.00311,0.09510,0.02510,0.00877,0.06871,0.07977,0.04632,  // Ñ - T
            0.03107,0.01138,0.00017,0.00215,0.01008,0.00467           // U - Z
    };
    /** Index of Coincidence for the Spanish language. */
    public static final double ICS = 0.07247;

    /**
     * Maps char `c` to its corresponding index.
     * @param c Input character.
     * @return The input char as an index.
     */
    public static int charToIndex(char c) {
        return c == 'Ñ' ? 14 : (c <= 'N' ? c - 'A' : c - 'A' + 0x0001);
    }

    /**
     * Maps index `i` to its corresponding char.
     * @param i Input index.
     * @return The input index as a char.
     */
    public static char indexToChar(int i) {
        int j = i == 14 ? 'Ñ' : (i <= 13 ? i + 'A' : i + 'A' - 0x0001);
        return (char)j;
    }

}
