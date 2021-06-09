import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

/** Vigenere encryption scheme. */
public class VigenereEncryption {

    /* Encryption key. */
    private String K;
    private int keyLength;

    /**
     * Creates a new `VigenereEncryption` object that encrypts/decrypts inputs
     * using the Vigenere Encryption scheme with the given encryption key.
     * @param key The encryption key.
     */
    public VigenereEncryption(String key) {
        this.K = key;
        this.keyLength = key.length();
    }

    /**
     * Gets the object's encryption key.
     * @return The encryption key.
     */
    public String getKey () {
        return this.K;
    }

    /* If `encrypt` is true, encrypts the `inputText`. Decrypts `inputText`
     * otherwise. */
    private String iterText(String inputText, boolean encrypt) {
        if (inputText == null)
            return null;

        int len = inputText.length();

        char[] outputText = new char[len];
        char[] chars = inputText.toCharArray();

        int j = 0;

        for (int i = 0; i < len; i++) {
            char ci = chars[i];

            if (ci == 'Ñ' || (ci >= 'A' && ci <= 'Z')) {
                int di = Vigenere.charToIndex(ci);
                int kj = Vigenere.charToIndex(this.K.charAt(j));

                int oi;
                if (encrypt) {
                    // Encrypt input text
                    oi = (di + kj) % 27;
                } else {
                    // Decrypt input text
                    oi = (di - kj + 27) % 27;
                }

                outputText[i] = Vigenere.indexToChar(oi);
                j = ++j == this.keyLength ? 0 : j;
            } else {
                outputText[i] = ci;
            }
        }

        return new String(outputText);
    }

    /**
     * Encrypts the input `message`.
     * @param message The input message.
     * @return The encrypted message, or ciphertext.
     */
    public String encrypt(String message) {
        return this.iterText(message, true);
    }

    /**
     * Decrypts the input `cipher`text.
     * @param cipher The input ciphertext.
     * @return The decrypted message, or plain text.
     */
    public String decrypt(String cipher) {
        return this.iterText(cipher, false);
    }

    public static void main(String[] args) {
        String m = "ATTACK AT DAWN";
        String k = "LIMON";

        var ve = new VigenereEncryption(k);

        String c = ve.encrypt(m);
        System.out.printf("Encrypted message: %s\n", c);

        String mc = ve.decrypt(c);
        System.out.printf("Plain text: %s\n", mc);

        // Encrypt a file with key `LIMON`.
        try {
            String plainText = Files.readString(Paths.get(args[0]));

            BufferedWriter writer = new BufferedWriter(new FileWriter(args[1]));
            writer.write(ve.encrypt(plainText.toUpperCase()));

            writer.close();
        } catch (IOException e) {
            e.printStackTrace ();
        }
    }

}
