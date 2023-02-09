import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HandshakeDigest {

    /*
     * Constructor -- initialise a digest for SHA-256
     */
    private MessageDigest digest;

    public HandshakeDigest() {
        try {
            this.digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Something is wrong");
        }
        
    }

    /*
     * Update digest with input data
     */
    public void update(byte[] input) {
        digest.update(input);
}


    /*
     * Compute final digest
     */
    public byte[] digest() {
        return digest.digest();
    }

}