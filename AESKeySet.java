import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

//import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class AESKeySet implements java.io.Serializable
{
	private Key key; 
	private IvParameterSpec IV; 

	public AESKeySet(Key newKey, IvParameterSpec newIV)
	{
		key = newKey;
		IV = newIV;
	}

	public void setKey(Key newKey)
	{
		key = newKey;
	}
	public void setIV(IvParameterSpec newIV)
	{
		IV = newIV;
	}
	public Key getKey()
	{
		return key;
	}
	public IvParameterSpec getIV()
	{
		return IV;
	}
}