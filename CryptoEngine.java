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


class CryptoEngine
{
	private KeyPairGenerator RSAKeyGen;
	private KeyGenerator AESKeyGen;
	public final int keySize;


    //NOTE: should we be using this cipher instead of a generic one? -John
	//private PaddedBufferedBlockCipher AESCipher;

//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-- CONSTRUCTOR
//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	
	public CryptoEngine() 
	{
		Security.addProvider(new BouncyCastleProvider());
		keySize = 128;

		//set up RSA objects
		try {
			RSAKeyGen = KeyPairGenerator.getInstance("RSA");
			RSAKeyGen.initialize(1024);
		} 
		catch (NoSuchAlgorithmException e) {
			System.out.print("WARNING:  CRYPTOENGINE;  RSA key gen failure");
		}

  		//set up AES objects
        try {
			AESKeyGen = KeyGenerator.getInstance("AES", "BC");
			AESKeyGen.init(128);
		} 
		catch (Exception e) {
			System.out.print("WARNING:  CRYPTOENGINE;  AES key gen failure");
		}
	}

//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-- KEY GENERATORS
//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

	public AESKeySet genAESKeySet()
	{
		//gent a key, IV pair and return it
	    return new AESKeySet(AESKeyGen.generateKey(), new IvParameterSpec(new byte[16]));
	}
	public KeyPair genRSAKeyPair() throws InvalidKeyException
	{
  		return RSAKeyGen.generateKeyPair();
	}

//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-- SIGNING AND VERIFICATION 
//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

	//return the signature as a byte array
	public byte[] RSASign(byte[] plainText, PrivateKey key) 
	{
  	    Signature signature;
  	    byte[] sigBytes = null;
		try {
			signature = Signature.getInstance("SHA1withRSA", "BC");
			signature.initSign(key, new SecureRandom()); 
			signature.update(plainText);
			signature.sign();
		} catch (Exception e) {
			System.out.print("WARNING:  CRYPTOENGINE;  RSA sign failure");
		}
		return sigBytes;
	}

	//return boolean of verified signature in byte form
	public boolean RSAVerify(byte[] plainText, byte[] sigBytes, PublicKey key) 
	{
		boolean verified = false;
	  	Signature signature;
		try {
			signature = Signature.getInstance("SHA1withRSA", "BC");
		    signature.initVerify(key);
			signature.update(plainText);
		    verified = signature.verify(sigBytes);
		} catch (Exception e) {
			System.out.print("WARNING:  CRYPTOENGINE;  RSA signature verification failure");
		}
		return verified;
	}
	

//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-- ENCRYPTION WRAPPERS AND DRIVER FUNCTIONS
//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	
	//wrappers for encrypt and decrypt
	public byte[] AESEncrypt(byte[] plainText, AESKeySet keySet) 
	{
		return DriverCoreFunction(plainText,  Cipher.ENCRYPT_MODE, keySet);
	}
	public byte[] AESDecrypt(byte[] cipherText, AESKeySet keySet) 
	{
		return DriverCoreFunction(cipherText, Cipher.DECRYPT_MODE, keySet);
	}
	//performs encryption and decryption for aAES
	public byte[] DriverCoreFunction(byte[] bytes, int mode, AESKeySet keySet) 
	{
		Cipher cipher = null;
		byte[]result = null;
		Key key = keySet.getKey();
		IvParameterSpec IV = keySet.getIV();


		try 
		{
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			cipher.init(mode, key, IV);
			cipher.doFinal(bytes);	
		} 
		catch (Exception e) {
			System.out.print("WARNING:  CRYPTOENGINE;  AES cipher failure; encrypt(1)/decrypt(2)="+mode);
		}
		 
		 return result;
	}

	public byte[] RSAEncrypt(byte[] plainText, Key key) 
	{		
		return DriverCoreFunction(plainText, Cipher.ENCRYPT_MODE, (Key)key);
	}
	public byte[] RSADecrypt(byte[] cipherText, Key key) 
	{
		return DriverCoreFunction(cipherText, Cipher.DECRYPT_MODE, (Key)key);
	}

	//performs encryption and decryption for RSA
	public byte[] DriverCoreFunction(byte[] bytes,  int mode, Key key) 
	{
		Cipher cipher = null;
		byte[]result = null;

		try 
		{
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(mode, key);	
			cipher.doFinal(bytes);	
		} 
		catch (Exception e) {
			System.out.print("WARNING:  CRYPTOENGINE;  RSA cipher failure;  encrypt(1)/decrypt(2)="+mode);
		}
		 
		 return result;
	}

//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-- EXTERNAL UTILITY FUNCTIONS
//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

	public String byteToStr(byte[] input)
	{
	    byte[] output = new byte[input.length];
	    int i = 0;

	    for (Byte current : input) {
	        output[i] = current;
	        i++;
	    }

		return new String(output,  Charset.forName("ISO-8859-1"));	
	}

	public byte[] strToByte( String input) 
	{
		try {
			return input.getBytes("ISO-8859-1");
		} catch (UnsupportedEncodingException e) {
			System.out.print("WARNING:  CRYPTOENGINE;  string to byte conversion failure");
			return null;
		}
	}
}

