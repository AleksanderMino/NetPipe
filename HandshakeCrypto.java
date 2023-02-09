import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.security.InvalidKeyException;
import java.security.Key;


public class HandshakeCrypto {

	private Key key;
	private X509Certificate cert;
	private Cipher cipher;
	
	public HandshakeCrypto(HandshakeCertificate handshakeCertificate) {
		this.cert = handshakeCertificate.getCertificate();
		this.key = cert.getPublicKey();
	}
	
	public HandshakeCrypto(byte[] keybytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keybytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		this.key = keyFactory.generatePrivate(keySpec);
		
	}
	
	public byte[] decrypt(byte[] ciphertext) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
			
			this.cipher = Cipher.getInstance("RSA");
			this.cipher.init(Cipher.DECRYPT_MODE, key);
			byte [] decr_bytes = this.cipher.doFinal(ciphertext);
			
			return decr_bytes;
	    }
	 
	public byte [] encrypt(byte[] plaintext) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
			
			this.cipher = Cipher.getInstance("RSA");
			this.cipher.init(Cipher.ENCRYPT_MODE,key);
			byte [] encr_bytes = this.cipher.doFinal(plaintext);

			return encr_bytes;
	    }
}
