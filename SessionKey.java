import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SessionKey {

    private SecretKey secretKey;
    
    public SessionKey (Integer keylength) {
        try{
            KeyGenerator generator = KeyGenerator.getInstance("AES");
      
            SecureRandom secRandom = new SecureRandom();
            generator.init(keylength, secRandom);

            this.secretKey = generator.generateKey();
            }

        catch (Exception e) {

        }
        
    }

   public SessionKey (byte[] keybytes) {
        this.secretKey = new SecretKeySpec(keybytes, "AES");
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public byte[] getKeyBytes() {
        return secretKey.getEncoded();
    }

}

