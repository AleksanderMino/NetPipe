import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.util.Base64;
//import HandshakeDigest.java;

public class FileDigest {
    public static void main(String[] args) {
        try {
            InputStream InputStream = new FileInputStream(args[0]);
            // InputStream.close();
            byte[] file_bytes = InputStream.readAllBytes();
            HandshakeDigest digest = new HandshakeDigest();
            digest.update(file_bytes);
            byte[] hash = digest.digest();
            // System.out.println(hash);
            String hash_encoded = Base64.getEncoder().encodeToString(hash);
            System.out.println(hash_encoded);
            InputStream.close();

        }
        catch (IOException e){
            e.printStackTrace();
        }
    }
}