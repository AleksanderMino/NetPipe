import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.io.*;

public class NetPipeServer {
    private static String PROGRAMNAME = NetPipeServer.class.getSimpleName();
    private static Arguments arguments;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--port=<portnumber>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", "servercert");
        arguments.setArgumentSpec("cacert", "cacert");
        arguments.setArgumentSpec("key", "serverprkey");

        try {
            arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }
    }

    /*
     * Main program.
     * Parse arguments on command line, wait for connection from client,
     * and call switcher to switch data between streams.
     */
    public static void main(String[] args) throws ClassNotFoundException, IOException, CertificateException,
            InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException,
            InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
        parseArgs(args);

        // CA's Certificate
        FileInputStream cacertInstream = new FileInputStream(arguments.get("cacert"));
        HandshakeCertificate cacert = new HandshakeCertificate(cacertInstream);

        ServerSocket serverSocket = null;

        int port = Integer.parseInt(arguments.get("port"));
        try {
            serverSocket = new ServerSocket(port);
        } catch (IOException ex) {
            System.err.printf("Error listening on port %d\n", port);
            System.exit(1);
        }
        Socket socket = null;
        while (true) {
            try {
                socket = serverSocket.accept();
            } catch (IOException ex) {
                System.out.printf("Error accepting connection on port %d\n", port);
                System.exit(1);
            }

            // Receive and verify ClientHello Message
            HandshakeMessage clientHello = HandshakeMessage.recv(socket);
            byte[] clientCertBytes = Base64.getDecoder().decode(clientHello.getParameter("Certificate"));
            HandshakeCertificate clientCert = new HandshakeCertificate(clientCertBytes);
            // FileInputStream clientcertInstream = new
            // FileInputStream(clientHello.getParameter("Certificate"));
            // HandshakeCertificate clientcert = new
            // HandshakeCertificate(clientcertInstream);
            try {
                clientCert.verify(cacert);
                System.out.println("Client's Certificate was verified");
            } catch (Exception e) {
                e.printStackTrace();
            }

            // Send ServerHello Message to client
            HandshakeMessage serverHello = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
            FileInputStream serverCertInstream = new FileInputStream(arguments.get("usercert"));
            HandshakeCertificate serverCert = new HandshakeCertificate(serverCertInstream);
            byte[] serverCertBytes = serverCert.getBytes();
            String clientCertBytesBase64 = Base64.getEncoder().encodeToString(serverCertBytes);
            serverHello.putParameter("Certificate", clientCertBytesBase64);
            serverHello.send(socket);

            // Receive SessionKey and SessionIv
            HandshakeMessage clientSession = HandshakeMessage.recv(socket);
            // private key of the server
            Path path = Paths.get(arguments.get("key"));
            byte[] privKeyByteArray = Files.readAllBytes(path);
            HandshakeCrypto clientFinishedCrypto = new HandshakeCrypto(privKeyByteArray);
            // Get the key and the IV from the client's session message
            byte[] sessionKeyBytesEncrypted = Base64.getDecoder().decode(clientSession.getParameter("SessionKey"));
            byte[] sessionIvBytesEncrypted = Base64.getDecoder().decode(clientSession.getParameter("SessionIV"));

            byte[] sessionKeyBytes = clientFinishedCrypto.decrypt(sessionKeyBytesEncrypted);
            SessionKey sessionKey = new SessionKey(sessionKeyBytes);
            byte[] sessionIvBytes = clientFinishedCrypto.decrypt(sessionIvBytesEncrypted);
            System.out.println("Key bytes " + Base64.getEncoder().encodeToString(sessionKeyBytes));
            System.out.println("IV bytes " + Base64.getEncoder().encodeToString(sessionIvBytes));

            System.out.println("Key and IV obtained successfully!!");

            // send serverfinished message
            // Get time
            HandshakeMessage serverFinished = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);
            DateTimeFormatter dataformat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            LocalDateTime now = LocalDateTime.now();
            String nowString = dataformat.format(now);
            byte[] nowBytes = nowString.getBytes();
            String nowEncoded = new String(nowBytes, StandardCharsets.UTF_8);
            byte[] nowEncodedBytes = nowEncoded.getBytes();

            // encrypt
            HandshakeCrypto serverFinishedCrypto = new HandshakeCrypto(privKeyByteArray);
            byte[] nowEncodedBytesEncr = serverFinishedCrypto.encrypt(nowEncodedBytes);
            String nowEncodeBytesEncrBase64 = Base64.getEncoder().encodeToString(nowEncodedBytesEncr);
            serverFinished.putParameter("TimeStamp", nowEncodeBytesEncrBase64);
            // Hash of the message that the server has sent
            HandshakeDigest serverFinishedDigest = new HandshakeDigest();
            byte[] serverHelloBytes = serverHello.getBytes();
            serverFinishedDigest.update(serverHelloBytes);
            byte[] serverHelloDigest = serverFinishedDigest.digest();
            byte[] serverHelloDigestEncrypted = serverFinishedCrypto.encrypt(serverHelloDigest);

            String serverHelloDigestEncryptedBase64 = Base64.getEncoder().encodeToString(serverHelloDigestEncrypted);
            serverFinished.putParameter("Signature", serverHelloDigestEncryptedBase64);
            serverFinished.send(socket);

            // Receive Client's Finished Message
            HandshakeMessage clientFinished = HandshakeMessage.recv(socket);
            byte[] clientSignatureEncrypted = Base64.getDecoder().decode(clientFinished.getParameter("Signature"));
            HandshakeCrypto decryptClientFinish = new HandshakeCrypto(clientCert);
            // reveived digest
            byte[] clientSignatureDigest = decryptClientFinish.decrypt(clientSignatureEncrypted);
            // calculate messages digest
            byte[] clientHelloBytes = clientHello.getBytes();
            byte[] clientSessionBytes = clientSession.getBytes();
            byte[] both_messages = new byte[clientHelloBytes.length + clientSessionBytes.length];

            System.arraycopy(clientHelloBytes, 0, both_messages, 0, clientHelloBytes.length);
            System.arraycopy(clientSessionBytes, 0, both_messages, clientHelloBytes.length, clientSessionBytes.length);

            HandshakeDigest clientFinishedDigest = new HandshakeDigest();
            clientFinishedDigest.update(both_messages);
            byte[] messagesDigest = clientFinishedDigest.digest();

            System.out.println(Base64.getEncoder().encodeToString(clientSignatureDigest));
            System.out.println(Base64.getEncoder().encodeToString(messagesDigest));

            // HandshakeMessage clientFinished = HandshakeMessage.recv(socket);

            try {
                InputStream serverInstream = socket.getInputStream();
                OutputStream serverOutstream = socket.getOutputStream();
                SessionCipher sessionCipherClient = new SessionCipher(sessionKey, sessionIvBytes);

                serverInstream = sessionCipherClient.openDecryptedInputStream(serverInstream);
                serverOutstream = sessionCipherClient.openEncryptedOutputStream(serverOutstream);

                Forwarder.forwardStreams(System.in, System.out, serverInstream,
                        serverOutstream, socket);
            } catch (IOException ex) {
                System.out.println("Stream forwarding error\n");
                System.exit(1);
            }
        }

    }
}
