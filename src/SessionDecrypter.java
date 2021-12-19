import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.*;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class SessionDecrypter
{   public SecretKey sessionkey;
    private IvParameterSpec IV;
    public Cipher cipher = null;

    SessionDecrypter(byte[] keybytes, byte[] ivbytes) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
    this.sessionkey = new SecretKeySpec(keybytes,"AES");
    this.IV = new IvParameterSpec(ivbytes);
    this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
    this.cipher.init(Cipher.DECRYPT_MODE, this.sessionkey, this.IV);
}
    CipherInputStream openCipherInputStream(InputStream input) {

        return new CipherInputStream(input, this.cipher);
    }
}
