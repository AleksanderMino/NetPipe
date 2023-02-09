import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


public class SessionCipher {

//    private byte[] keybytes;
    private byte[] ivbytes;
    private SecretKey secret_key;
    private IvParameterSpec ivspec;
    private CipherOutputStream cipherOutput;
    private SessionKey key;
    private CipherInputStream cipherInput;

    public SessionCipher (SessionKey key) throws NoSuchAlgorithmException, NoSuchPaddingException{
        
        this.secret_key = key.getSecretKey();
//        this.keybytes = key.getKeyBytes(); 
        this.key  = key;
        byte[] iv = new byte[Cipher.getInstance("AES/CTR/NoPadding").getBlockSize()];
        SecureRandom secRandom = new SecureRandom();
        secRandom.nextBytes(iv);
        this.ivspec = new IvParameterSpec(iv);
        // this.iv = new IvParameterSpec(keybytes);
        this.ivbytes = ivspec.getIV();

    }

    public SessionCipher (SessionKey key, byte[] ivbytes) {

        this.key = key;
        this.ivbytes = ivbytes;

        this.secret_key = key.getSecretKey(); 

        this.ivspec = new IvParameterSpec(ivbytes); 
    }

    public CipherOutputStream openEncryptedOutputStream (OutputStream output) {
        try {

            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secret_key, ivspec);

            cipherOutput = new CipherOutputStream(output, cipher);
            
        } catch (Exception e) {
         
        }
        
        return cipherOutput;
    }

     public CipherInputStream openDecryptedInputStream (InputStream input) {
        try {

            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secret_key, ivspec);

            cipherInput = new CipherInputStream(input, cipher);
            
        } catch (Exception e) {
         
        }
        
        return cipherInput;
    }

    public SessionKey getSessionKey(){
        
        return key;
    }

    public byte[] getIVBytes(){
        
        return ivbytes;

    }
}