import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.PublicKey;
import java.security.PrivateKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.KeyGenerator;
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