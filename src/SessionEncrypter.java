import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;

public class SessionEncrypter {
    private final byte[] IV_byte;
    public Cipher cipher = null;
    public SecretKey sessionkey;
    public SessionEncrypter(Integer keylength) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidParameterSpecException {
        KeyGenerator keyGenerator =KeyGenerator.getInstance("AES");
        keyGenerator.init(keylength);
        sessionkey =keyGenerator.generateKey();
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, sessionkey);
        IV_byte = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
    }
    SessionEncrypter(byte[] keybytes, byte[] ivbytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        sessionkey = new SecretKeySpec(keybytes,"AES");
        IV_byte = ivbytes;
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, sessionkey, new IvParameterSpec(ivbytes));
    }

    public CipherOutputStream openCipherOutputStream(OutputStream output) {
        return new CipherOutputStream(output,cipher);
    }
    public byte[] getKeyBytes() {
        return this.sessionkey.getEncoded();
    }
    public byte[] getIVBytes() {
        return this.IV_byte;
    }

}




