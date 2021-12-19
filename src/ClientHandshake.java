/**
 * Client side of the handshake.
 */

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.Socket;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class ClientHandshake {
    /*
     * The parameters below should be learned by the client
     * through the handshake protocol.
     */

    /* Session host/port  */
    public static String sessionHost = "localhost";
    public static int sessionPort = 12345;

    /* Security parameters key/iv should also go here. Fill in! */
    public byte[] sessionKey;
    public byte[] sessionIV;


    /**
     * Run client handshake protocol on a handshake socket.
     * Here, we do nothing, for now.
     */
  /*  public void ClientHello(Socket socket,String   Ceruser) throws CertificateException, IOException {
        HandshakeMessage clienthello = new HandshakeMessage();
        X509Certificate ClientCert = VerifyCertificate.findCertificate(Ceruser);

        clienthello.putParameter("MessageType","ClientHello");
        clienthello.putParameter("Certificate",Base64.getEncoder().encodeToString(ClientCert.getEncoded()));
        clienthello.send(socket);
        Logger.log( " ClientHello have sent.");
    }
    public void ServerReceiveHello (Socket socket, String caPath) {
        HandshakeMessage serverHelloMessage = new HandshakeMessage();

        try {
            serverHelloMessage.recv(socket);
            if (serverHelloMessage.getParameter("MessageType").equals("ServerHello")) {
                String serverCertificateString = serverHelloMessage.getParameter("Certificate");
                byte[] certificateByte = Base64.getDecoder().decode(serverCertificateString);
                CertificateFactory certificateFac = CertificateFactory.getInstance("X.509");
                InputStream inputStream = new ByteArrayInputStream(certificateByte);
                X509Certificate serverCertificate = (X509Certificate) certificateFac.generateCertificate(inputStream);
                X509Certificate caCertificate = VerifyCertificate.findCertificate(caPath);
                VerifyCertificate.verifyCertificate(caCertificate, serverCertificate); //Ensure the validation
                Logger.log("Server certificate verification successful!");
            } else {
                throw new Exception();
            }
        } catch (IOException e) {
            e.printStackTrace();
            Logger.log("Fail to receive the ServerHello message!");
        } catch (CertificateException e) {
            e.printStackTrace();
            Logger.log("Fail to decode the certificate!");
        } catch (Exception e) {
            e.printStackTrace();
            Logger.log("Fail to verify the server certificate!");
        }
    }
    public void ClientForward(Socket socket,String TargetHost,String TargetPort) throws IOException {
        HandshakeMessage ClientForwardMessage = new HandshakeMessage();
        ClientForwardMessage.putParameter("MessageType", "Forward");
        ClientForwardMessage.putParameter("TargetHost", TargetHost);
        ClientForwardMessage.putParameter("TargetPort", TargetPort);
        ClientForwardMessage.send(socket);
        Logger.log("ClientForward sent.");
    }

    public void recvSession (Socket socket, String privateKeyFile) {
        HandshakeMessage sessionMessage = new HandshakeMessage();
        try {
            sessionMessage.recv(socket);
            if (sessionMessage.getParameter("MessageType").equals("Session")) {
                PrivateKey clientPrivateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(privateKeyFile);
                sessionKey = HandshakeCrypto.decrypt(Base64.getDecoder().decode(sessionMessage.getParameter("SessionKey")), clientPrivateKey);
                sessionIV = HandshakeCrypto.decrypt(Base64.getDecoder().decode(sessionMessage.getParameter("SessionIV")), clientPrivateKey);
                sessionHost = sessionMessage.getParameter("SessionHost");
                sessionPort = Integer.parseInt(sessionMessage.getParameter("SessionPort"));
                Logger.log("Session message received!");
            } else {
                throw new Exception();
            }
        } catch (IOException e) {
            e.printStackTrace();
            Logger.log("Fail to receive the session message!");
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException
                | NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }*/
    public ClientHandshake(Socket handshakeSocket, String targethost, String targetport, String cacert, String usercert, String key) throws Exception {
        HandshakeMessage clienthello = new HandshakeMessage();
        X509Certificate ClientCert = VerifyCertificate.findCertificate(usercert);

        clienthello.putParameter("MessageType", "ClientHello");
        clienthello.putParameter("Certificate", Base64.getEncoder().encodeToString(ClientCert.getEncoded()));
        clienthello.send(handshakeSocket);
        Logger.log(" ClientHello have sent.");

        HandshakeMessage serverHelloMessage = new HandshakeMessage();
        serverHelloMessage.recv(handshakeSocket);
        if (serverHelloMessage.getParameter("MessageType").equals("ServerHello")) {
            String serverCertificateString = serverHelloMessage.getParameter("Certificate");
            byte[] certificateByte = Base64.getDecoder().decode(serverCertificateString);
            CertificateFactory certificateFac = CertificateFactory.getInstance("X.509");
            InputStream inputStream = new ByteArrayInputStream(certificateByte);
            X509Certificate serverCertificate = (X509Certificate) certificateFac.generateCertificate(inputStream);
            X509Certificate caCertificate = VerifyCertificate.findCertificate(cacert);
            VerifyCertificate.verifyCertificate(caCertificate, serverCertificate); //Ensure the validation
            Logger.log("Server certificate verification successful!");
        } else {
            throw new Exception();
        }


        HandshakeMessage ClientForwardMessage = new HandshakeMessage();
        ClientForwardMessage.putParameter("MessageType", "Forward");
        ClientForwardMessage.putParameter("TargetHost", targethost);
        ClientForwardMessage.putParameter("TargetPort", targetport);
        ClientForwardMessage.send(handshakeSocket);
        Logger.log("ClientForward sent.");

        HandshakeMessage sessionMessage = new HandshakeMessage();
        try {
            sessionMessage.recv(handshakeSocket);
            if (sessionMessage.getParameter("MessageType").equals("Session")) {
                PrivateKey clientPrivateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(key);
                sessionKey = HandshakeCrypto.decrypt(Base64.getDecoder().decode(sessionMessage.getParameter("SessionKey")), clientPrivateKey);
                sessionIV = HandshakeCrypto.decrypt(Base64.getDecoder().decode(sessionMessage.getParameter("SessionIV")), clientPrivateKey);
                sessionHost = sessionMessage.getParameter("SessionHost");
                sessionPort = Integer.parseInt(sessionMessage.getParameter("SessionPort"));
                Logger.log("Session message received!");
            } else {
                throw new Exception();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}



