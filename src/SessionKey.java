import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import java.security.NoSuchAlgorithmException;
import javax.crypto.spec.SecretKeySpec;

public class SessionKey {

    public SecretKey sessionkey;
    private byte[] sessionkeybyte;
    public SessionKey(Integer keylength) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator =KeyGenerator.getInstance("AES");
        keyGenerator.init(keylength);
        this.sessionkey =keyGenerator.generateKey();

    }
    public SessionKey(byte[] keybytes){
        int keyLength = keybytes.length;
        this.sessionkey=new SecretKeySpec(keybytes, 0, keyLength,"AES");
        }
        public SecretKey getSecretKey()
        {
            return this.sessionkey;
        }
        public byte[] getKeyBytes(){
        this.sessionkeybyte=this.sessionkey.getEncoded();
        return this.sessionkeybyte;
        }
}



