import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.*;
import java.text.ParseException;
import java.util.Base64;

public class VerifyCertificate {

    private static String certificatePath;

    public static void main(String[] args) throws CertificateException, FileNotFoundException, ParseException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        X509Certificate CA = findCertificate(args[0]);
        X509Certificate user = findCertificate(args[1]);
        verifyCertificate(CA, user);
    }

    public static void verifyCertificate(X509Certificate CA, X509Certificate user) throws ParseException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        System.out.println(CA.getSubjectX500Principal());
        System.out.println(user.getSubjectX500Principal());
        try {
            CA.verify(CA.getPublicKey());
            user.verify(CA.getPublicKey());
            CA.checkValidity();
            user.checkValidity();
            System.out.println("Pass");
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    public static X509Certificate findCertificate(String certificatePath) throws FileNotFoundException, CertificateException {
        CertificateFactory certificateFac = CertificateFactory.getInstance("X.509");
        FileInputStream certificateFile = new FileInputStream (certificatePath);
        return (X509Certificate) certificateFac.generateCertificate(certificateFile);
    }

}


