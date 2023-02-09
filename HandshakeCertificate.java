import java.io.ByteArrayInputStream;
import java.security.cert.CertificateEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.io.InputStream;
// import java.io.FileInputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;

public class HandshakeCertificate {

    private X509Certificate cert;
    private X509Certificate ca_cert;
    private PublicKey ca_key;

    public HandshakeCertificate(InputStream instream) throws CertificateException {
        // this.cert = X509Certificate.getInstance(instream);
        CertificateFactory cert_fact = CertificateFactory.getInstance("X.509");
        this.cert = (X509Certificate) cert_fact.generateCertificate(instream);
    }

    public HandshakeCertificate(byte[] certbytes) throws CertificateException {
        CertificateFactory cert_fact = CertificateFactory.getInstance("X.509");

        InputStream instream = new ByteArrayInputStream(certbytes);
        this.cert = (X509Certificate) cert_fact.generateCertificate(instream);
        // this.cert = X509Certificate.getInstance(certbytes);
    }

    public byte[] getBytes() throws CertificateEncodingException {
        return this.cert.getEncoded();
    }

    public X509Certificate getCertificate() {
        return this.cert;
    }

    public void verify(HandshakeCertificate cacert)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException,
            SignatureException {
        this.ca_cert = cacert.getCertificate();
        this.ca_key = ca_cert.getPublicKey();
        this.cert.verify(ca_key);
    }

    public String getCN() {
    	
       Principal subjectDN = this.cert.getSubjectX500Principal();
       String subjectDNstring = subjectDN.toString();
       String[] splitted = subjectDNstring.split("[=,]");
       String CN = splitted[3];
       return CN;
    }

    public String getEmail() {

    	Principal subjectDN = this.cert.getSubjectX500Principal();
        String subjectDNstring = subjectDN.toString();
        String[] splitted = subjectDNstring.split("[=,]");
        String email = splitted[1];
        return email;
    }

  

}
