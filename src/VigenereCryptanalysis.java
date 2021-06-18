import java.io.*;
import java.util.Arrays;
import java.util.Random;

/** Vigenere encryption scheme cryptanalysis. */
public class VigenereCryptanalysis {

    private static final double EPS = 0.001;

    private Random rand;
    /* Character frequencies in given ciphertext. */
    private double[] q;
    private String ciphertext;

    /**
     * Creates a new VigenereCryptanalysis object.
     * @param cipher The ciphertext.
     */
    public VigenereCryptanalysis(String cipher) {
        this.rand = new Random();
        this.q = new double[27];
        this.ciphertext = cipher.replaceAll("[^A-ZÑ]","");
    }

    /* Counts character frequencies in a given block `B`. */
    private void frequencies(String B) {
        Arrays.fill(q, 0.0);
        for (char ci: B.toCharArray())
            q[Vigenere.charToIndex(ci)]++;
        for (int i = 0; i < 27; i++)
            q[i] /= B.length();
    }

    /* Creates a block of characters, splitting the ciphertext into batches of
     * size `period` and taking the character at position `column`.
     *
     * The block looks like this: `C{0+c}C{p+c}C{2p+c}...`
     */
    private String block(int period, int column) {
        int l = ciphertext.length();

        // The size of the block
        int k = l % period > column ? l/period + 1 : l/period;
        char[] B = new char[k];
        for (int i = 0; i < k; i++)
            B[i] = ciphertext.charAt(i*period + column);

        // Block B = c{0+col}c{p+col}c{2p+col}...
        return new String(B);
    }

    /**
     * Guesses the length of the key used to encrypt the plain text.
     * @return The length of the key.
     */
    public int keyLength() {
        int l = ciphertext.length();

        for (int t = 1; t <= l; t++) {
            // Try a random block
            int r = rand.nextInt(t);
            String Br = block(t, r);
            // Count frequencies of each character
            frequencies(Br);
            // Compute I
            double I = 0.0;
            for (double qi : q)
                I += qi*qi;
            // Value of `t` that approximates the key length
            if (Math.abs(I - Vigenere.ICS) < EPS)
                return t;
        }

        return l;
    }

    /* Guesses the offset used to shift the characters in block `B`. */
    private int offset(String B) {
        // Frequencies in block B
        frequencies(B);
        int d = 0;
        double dif = 1.0;
        for (int k = 0; k < 27; k++) {
            double Ik = 0.0;
            for (int i = 0; i < 27; i++)
                Ik += Vigenere.p[i] * q[(i+k) % 27];

            // Value of k that best approximates the offset
            double approx = Math.abs(Ik - Vigenere.ICS);
            if (approx < dif){
                d = k;
                dif = approx;
            }
        }
        return d;
    }

    /**
     * Generates a possible key of given `length`.
     * @param length The length of the key.
     * @return The key.
     */
    public String generateKey(int length) {
        char[] key = new char[length];
        for (int r = 0; r < length; r++) {
            // Block Br to decrypt
            String Br = block(length, r);
            // Offset
            key[r] = Vigenere.indexToChar(offset(Br));
        }
        return new String(key);
    }

    public static void main(String[] args) {
        String cipher;

        try {
            File file = new File (args[0]);
            Reader reader = new InputStreamReader (new FileInputStream (file), "UTF-8");
            char[] stream = new char[(int) file.length()];
            reader.read (stream);

            cipher = new String (stream);
            reader.close();
        } catch (IOException e) {
            e.printStackTrace ();
            return;
        }

        System.out.printf("Cipher text: %s...\n", cipher.substring(0, 50));

        var ve = new VigenereEncryption("LIMON");

        String m = ve.decrypt(cipher);
        System.out.printf("Plain text: %s...\n", m.substring(0, 50));

        var vc = new VigenereCryptanalysis(cipher);

        int kl = vc.keyLength();
        System.out.printf("Key length: %d\n", kl);

        String key = vc.generateKey(kl);
        System.out.printf("Key (guess): %s\n", key);

        System.out.printf("Original message: %s...\n",
                new VigenereEncryption(key).decrypt(cipher).substring(0, 50));
    }

}
