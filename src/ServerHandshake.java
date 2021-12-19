/**
 * Server side of the handshake.
 */

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.Socket;
import java.net.ServerSocket;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;
import java.util.Properties;


public class ServerHandshake{
    /*
     * The parameters below should be learned by the server
     * through the handshake protocol.
     */

    /* Session host/port, and the corresponding ServerSocket  */
    public static ServerSocket sessionSocket;
    public static String sessionHost;
    public static int sessionPort;

    /* The final destination -- simulate handshake with constants */
    public static String targetHost = "localhost";
    public static int targetPort = 6789;

    /* Security parameters key/iv should also go here. Fill in! */
    public byte[] sessionKey;
    public byte[] sessionIV;
    public X509Certificate clientCertificate;
    private Object String;

    /*
     * Run server handshake protocol on a handshake socket.
     * Here, we simulate the handshake by just creating a new socket
     * with a preassigned port number for the session.
     */
    public ServerHandshake(Socket handshakeSocket, java.lang.String cacert, java.lang.String usercert) throws Exception {
        sessionSocket = new ServerSocket(12345);
        sessionHost = sessionSocket.getInetAddress().getHostName();
        sessionPort = sessionSocket.getLocalPort();

        //ClientHello(handshakeSocket, ForwardServer.arguments.get("cacert"));
        ClientHello(handshakeSocket, cacert);
        //serverHello(handshakeSocket,ForwardServer.arguments.get("usercert"));
        serverHello(handshakeSocket,usercert);
        HandshakeMessage GetFromFuckingClientCall = new HandshakeMessage();
        GetFromFuckingClientCall.recv(handshakeSocket);
        targetHost = GetFromFuckingClientCall.getParameter("TargetHost");
        targetPort = Integer.parseInt(GetFromFuckingClientCall.getParameter("TargetPort"));
        session( handshakeSocket);
        handshakeSocket.close();
        System.out.println("Handshake is done.");
    }
    public void ClientHello (Socket socket, String caroute) throws Exception {
        CertificateFactory certificatebyte = CertificateFactory.getInstance("X.509");
        HandshakeMessage clientHelloMessage = new HandshakeMessage();
        clientHelloMessage.recv(socket);
        if (clientHelloMessage.getParameter("MessageType").equals("ClientHello")) {
            byte[] CertificateByte = Base64.getDecoder().decode(clientHelloMessage.getParameter("Certificate"));
            InputStream file = new ByteArrayInputStream(CertificateByte);
            clientCertificate = (X509Certificate) certificatebyte.generateCertificate(file);
            X509Certificate caCertificate = VerifyCertificate.findCertificate(caroute);
            VerifyCertificate.verifyCertificate(caCertificate, clientCertificate);
            Logger.log("Client's certificate verify successfully!");
        } else {
            Logger.log("Message type error.");
            throw new Exception();
        }
    }
        public void serverHello (Socket socket, String certificatePath) throws IOException, CertificateException {
            HandshakeMessage serverHelloMessage = new HandshakeMessage();
            X509Certificate serverCertificate = VerifyCertificate.findCertificate(certificatePath);
            serverHelloMessage.putParameter("MessageType","ServerHello");
            serverHelloMessage.putParameter("Certificate",Base64.getEncoder().encodeToString(serverCertificate.getEncoded()));
            serverHelloMessage.send(socket);
            Logger.log("ServerHello message send successfully!");


    }
    public void receiveForward (Socket socket) throws Exception {
        HandshakeMessage forwardMessage = new HandshakeMessage();
        forwardMessage.recv(socket);
        if (forwardMessage.getParameter("MessageType").equals("Forward")) {
            targetHost = forwardMessage.getParameter("TargetHost");
            targetPort = Integer.parseInt(forwardMessage.getParameter("TargetPort"));
            Logger.log("Server forward verify successfully");
        } else {
            Logger.log("Forward message verify failed ");
            throw new Exception();
        }
    }
        public void session (Socket socket) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
            HandshakeMessage sessionMessage = new HandshakeMessage();

            sessionMessage.putParameter("MessageType","Session");
            SessionEncrypter sessionEncrypter = new SessionEncrypter(128);
            sessionKey = sessionEncrypter.getKeyBytes();
            sessionIV = sessionEncrypter.getIVBytes();
            PublicKey clientPublicKey = clientCertificate.getPublicKey();
            byte[] sessionKeyEncrypted =  HandshakeCrypto.encrypt(sessionKey, clientPublicKey);
            byte[] sessionIVEncrypted = HandshakeCrypto.encrypt(sessionIV, clientPublicKey);
            sessionMessage.putParameter("MessageType", "Session");
            sessionMessage.putParameter("SessionKey", Base64.getEncoder().encodeToString(sessionKeyEncrypted));
            sessionMessage.putParameter("SessionIV", Base64.getEncoder().encodeToString(sessionIVEncrypted));
            sessionMessage.putParameter("SessionHost", sessionHost);
            sessionMessage.putParameter("SessionPort", Integer.toString(sessionPort));
            sessionMessage.send(socket);
            Logger.log("Session message sent successfully!");
            Logger.log("finished.");


        }

    }

