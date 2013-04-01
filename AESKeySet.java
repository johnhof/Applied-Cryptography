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
	private byte[] byteIV;

	public AESKeySet(Key newKey, IvParameterSpec newIV)
	{
		key = newKey;
		byteIV = newIV.getIV();
	}

	public void setKey(Key newKey)
	{
		key = newKey;
	}
	public void setIV(IvParameterSpec newIV)
	{
		byteIV = newIV.getIV();
	}
	public Key getKey()
	{
		return key;
	}
	public IvParameterSpec getIV()
	{
		return new IvParameterSpec(byteIV);
	}
}