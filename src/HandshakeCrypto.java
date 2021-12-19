import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import javax.crypto.*;

public class HandshakeCrypto {
    public static byte[] encrypt(byte[] plaintext, Key key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(byte[] ciphertext, Key key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(ciphertext);
    }

    public static PublicKey getPublicKeyFromCertFile(String certfile) throws FileNotFoundException, CertificateException {
        InputStream ins = new FileInputStream(certfile);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) factory.generateCertificate(ins);
        PublicKey publicKey = certificate.getPublicKey();
        return publicKey;
    }

    public static PrivateKey getPrivateKeyFromKeyFile(String keyfile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path keyfile_path = Paths.get(keyfile);
        byte[] privateKey_byte = Files.readAllBytes(keyfile_path);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey_byte);
        KeyFactory privateKey_fac = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = privateKey_fac.generatePrivate(keySpec);
        return privateKey;
    }
}