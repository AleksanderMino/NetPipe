import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import java.io.*;

public class NetPipeClient {
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--host=<hostname>");
        System.err.println(indent + "--port=<portnumber>");
        System.err.println(indent + "--usercert=<clientcert>");
        System.err.println(indent + "--cacert=<cacert>");
        System.err.println(indent + "--key=<clientprkey>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("host", "hostname");
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", "clientcert");
        arguments.setArgumentSpec("cacert", "cacert");
        arguments.setArgumentSpec("key", "clientprkey");

        try {
            arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }
    }

    /*
     * Main program.
     * Parse arguments on command line, connect to server,
     * and call forwarder to forward data between streams.
     */
    public static void main(String[] args) throws CertificateException, InvalidKeyException,
            NoSuchAlgorithmException, NoSuchProviderException, SignatureException, NumberFormatException,
            UnknownHostException, IOException, ClassNotFoundException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        // Socket socket = null;

        parseArgs(args);
        // String host = arguments.get("host");
        // int port = Integer.parseInt(arguments.get("port"));
        FileInputStream cacertInstream = new FileInputStream(arguments.get("cacert"));
        FileInputStream clientCertInstream = new FileInputStream(arguments.get("usercert"));
        HandshakeCertificate cacert = new HandshakeCertificate(cacertInstream);

        HandshakeCertificate clientCert = new HandshakeCertificate(clientCertInstream);
        byte[] clientCertBytes = clientCert.getBytes();
        String clientCertBytesBase64 = Base64.getEncoder().encodeToString(clientCertBytes);
        // String usercertpem = Base64.getEncoder().encodeToString(cert.getBytes());
        // System.out.println(usercertpem);
        clientCert.verify(cacert);
        System.out.println("User's certificate verified");
        System.out.println("Connect to " + arguments.get("host") + ":" + Integer.parseInt(arguments.get("port")));

        // Send client hello message to the server which contains the
        // certificate of the user

        Socket socket = new Socket(arguments.get("host"), Integer.parseInt(arguments.get("port")));
        System.out.println();
        HandshakeMessage clientHello = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
        clientHello.putParameter("Certificate", clientCertBytesBase64);
        clientHello.send(socket);

        // receive server hello message with the servers certificate
        HandshakeMessage serverHello = HandshakeMessage.recv(socket);
        // FileInputStream servercertInstream = new
        // FileInputStream(serverHello.getParameter("Certificate"));
        // HandshakeCertificate servercert = new
        // HandshakeCertificate(servercertInstream);
        byte[] serverCertBytes = Base64.getDecoder().decode(serverHello.getParameter("Certificate"));
        HandshakeCertificate serverCert = new HandshakeCertificate(serverCertBytes);
        serverCert.verify(cacert);
        try {
            serverCert.verify(cacert);
            System.out.println("Server's Certificate was verified");
        } catch (Exception e) {
            e.printStackTrace();
        }

        // The client creates the key and the IV for the session
        // Create session key and get the bytes
        SessionKey sessionKey = new SessionKey(128);
        byte[] sessionKeyBytes = sessionKey.getKeyBytes();
        // System.out.println("Key bytes " +
        // Base64.getEncoder().encodeToString(sessionKeyBytes));
        // create a SessionCipher object, use the key as an input
        // and get the IV bytes
        SessionCipher sessionCipher = new SessionCipher(sessionKey);
        byte[] sessionIvBytes = sessionCipher.getIVBytes();
        // System.out.println("IV bytes " +
        // Base64.getEncoder().encodeToString(sessionIvBytes));

        HandshakeCrypto handshakeCrypto = new HandshakeCrypto(serverCert);
        byte[] sessionKeyBytesEncrypted = handshakeCrypto.encrypt(sessionKeyBytes);
        byte[] sessionIvBytesEncrypted = handshakeCrypto.encrypt(sessionIvBytes);

        String sessionKeyBytesEncryptedEncod = Base64.getEncoder().encodeToString(sessionKeyBytesEncrypted);
        String sessionIvBytesEncryptedEncod = Base64.getEncoder().encodeToString(sessionIvBytesEncrypted);
        // System.out.println(sessionIvBytesEncryptedEncod);

        HandshakeMessage clientSession = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
        clientSession.putParameter("SessionKey", sessionKeyBytesEncryptedEncod);
        clientSession.putParameter("SessionIV", sessionIvBytesEncryptedEncod);
        clientSession.send(socket);

        // Receive server's Finished message
        HandshakeMessage serverFinished = HandshakeMessage.recv(socket);

        // Check the signature, decrypt the hash of the server's message
        byte[] serverSignatureEncrypted = Base64.getDecoder().decode(serverFinished.getParameter("Signature"));
        HandshakeCrypto serverFinishedCrypto = new HandshakeCrypto(serverCert);
        byte[] hashServerMessage = serverFinishedCrypto.decrypt(serverSignatureEncrypted);
        // compute the hash of the server's message to compare
        HandshakeDigest serverFinishedDigest = new HandshakeDigest();
        byte[] serverHelloBytes = serverHello.getBytes();
        serverFinishedDigest.update(serverHelloBytes);
        byte[] serverHelloDigest = serverFinishedDigest.digest();
        System.out.println(Base64.getEncoder().encodeToString(hashServerMessage));
        System.out.println();
        System.out.println(Base64.getEncoder().encodeToString(serverHelloDigest));

        if (Arrays.equals(hashServerMessage, serverHelloDigest)) {
            System.out.println("The two hash values are the same");

        } else {
            System.out.println("They are not the same");

        }

        HandshakeMessage clientFinished = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTFINISHED);
        DateTimeFormatter dataformat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        LocalDateTime now = LocalDateTime.now();
        String nowString = dataformat.format(now);
        byte[] nowBytes = nowString.getBytes();
        String nowEncoded = new String(nowBytes, StandardCharsets.UTF_8);
        byte[] nowEncodedBytes = nowEncoded.getBytes();

        // get private key of the client
        Path path = Paths.get(arguments.get("key"));
        byte[] privKeyByteArray = Files.readAllBytes(path);
        // encrypt
        HandshakeCrypto clientFinishedCrypto = new HandshakeCrypto(privKeyByteArray);
        byte[] nowEncodedBytesEncr = clientFinishedCrypto.encrypt(nowEncodedBytes);
        String nowEncodeBytesEncrBase64 = Base64.getEncoder().encodeToString(nowEncodedBytesEncr);
        clientFinished.putParameter("TimeStamp", nowEncodeBytesEncrBase64);
        // clientFinished.putParameter("Signature", );
        byte[] clientHelloBytes = clientHello.getBytes();
        byte[] clientSessionBytes = clientSession.getBytes();
        byte[] both_messages = new byte[clientHelloBytes.length + clientSessionBytes.length];

        System.arraycopy(clientHelloBytes, 0, both_messages, 0, clientHelloBytes.length);
        System.arraycopy(clientSessionBytes, 0, both_messages, clientHelloBytes.length, clientSessionBytes.length);

        HandshakeDigest clientFinishedDigest = new HandshakeDigest();
        clientFinishedDigest.update(both_messages);
        byte[] messagesDigest = clientFinishedDigest.digest();
        byte[] messagesDigestEncrypted = clientFinishedCrypto.encrypt(messagesDigest);
        String messagesDigestEncryptedBase64 = Base64.getEncoder().encodeToString(messagesDigestEncrypted);
        clientFinished.putParameter("Signature", messagesDigestEncryptedBase64);
        clientFinished.send(socket);

        // try {
        // socket = new Socket(host, port);
        // } catch (IOException ex) {
        // System.err.printf("Can't connect to server at %s:%d\n", host, port);
        // System.exit(1);
        // }

        try {
            InputStream clientInstream = socket.getInputStream();
            OutputStream clientOutstream = socket.getOutputStream();

            SessionCipher sessionCipherClient = new SessionCipher(sessionKey, sessionIvBytes);

            clientInstream = sessionCipherClient.openDecryptedInputStream(clientInstream);
            clientOutstream = sessionCipherClient.openEncryptedOutputStream(clientOutstream);
            Forwarder.forwardStreams(System.in, System.out, clientInstream,
                    clientOutstream, socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        }
    }

}
