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

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;


class CryptoDriver
{
	private KeyPairGenerator RSAKeyGen;
	//KeyPair RSAKeyPair;
	//CipherParameters IVAndKey;
	private KeyGenerator AESKeyGen;
	//Key AESKey;
	IvParameterSpec IV;
	public final int keySize;


    //NOTE: should we be using this cipher instead of a generic one? -John
	private PaddedBufferedBlockCipher AESCipher;

//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-- CONSTRUCTOR
//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	
	public CryptoDriver() throws NoSuchAlgorithmException, NoSuchProviderException
	{
		Security.addProvider(new BouncyCastleProvider());
		keySize = 128;

		//set up RSA objects
		RSAKeyGen = KeyPairGenerator.getInstance("RSA");
		RSAKeyGen.initialize(1024);

  		//set up AES objects
        AESKeyGen = KeyGenerator.getInstance("AES", "BC");
        AESKeyGen.init(128);

        //NOTE: should this be done for each key? - John
        IV = new IvParameterSpec(new byte[16]);


    	//NOTE: should we be using this cipher instead of a generic one? -John
 	    //AESCipher = new PaddedBufferedBlockCipher( new CBCBlockCipher(new AESEngine()));

	}

//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-- KEY GENERATORS
//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

	public Key genAESKey()
	{

        //NOTE: should this be done and returned for each key? - John
        //IV = new IvParameterSpec(new byte[16]);
	    return AESKeyGen.generateKey();
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
		try
		{
	  	    Signature signature = Signature.getInstance("SHA1withRSA", "BC");
	  	    signature.initSign(key, new SecureRandom());
			signature.update(plainText);
			return signature.sign();
		}
		catch(InvalidKeyException e){System.out.println("CRYPTO ENGINE ERROR:  RSAVerify;  Invalid Key");}
		catch(NoSuchAlgorithmException e){System.out.println("CRYPTO ENGINE ERROR: RSAVerify;  No Such Algorithm");}
		catch(SignatureException e){System.out.println("CRYPTO ENGINE ERROR:  RSAVerify;  Signature Exception");}
		catch(NoSuchProviderException e){System.out.println("CRYPTO ENGINE  ERROR: RSAVerify;  No Such Provider");}

		return null;
	}

	//return boolean of verified signature in byte form
	public boolean RSAVerify(byte[] sigBytes, PublicKey key) 
	{
		try
		{
	  	    Signature signature = Signature.getInstance("SHA1withRSA", "BC");
		    signature.initVerify(key);
			signature.update(sigBytes);
	    	return signature.verify(sigBytes);
		}
		catch(InvalidKeyException e){System.out.println("CRYPTO ENGINE ERROR:  RSAVerify;  Invalid Key");}
		catch(NoSuchAlgorithmException e){System.out.println("CRYPTO ENGINE ERROR: RSAVerify;  No Such Algorithm");}
		catch(SignatureException e){System.out.println("CRYPTO ENGINE ERROR:  RSAVerify;  Signature Exception");}
		catch(NoSuchProviderException e){System.out.println("CRYPTO ENGINE  ERROR: RSAVerify;  No Such Provider");}

		return false;
	}
	

//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-- ENCRYPTION WRAPPERS AND DRIVER FUNCTIONS
//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	
	//wrappers for encrypt and decrypt
	public byte[] AESEncrypt(byte[] plainText, Key key)
	{
		return EngineCoreFunction(plainText, 1, Cipher.ENCRYPT_MODE, key);
	}

	public byte[] AESDecrypt(byte[] cipherText, Key key) 
	{
		return EngineCoreFunction(cipherText, 1, Cipher.DECRYPT_MODE, key);
	}

	public byte[] RSAEncrypt(byte[] plainText, PublicKey key)
	{		
		return EngineCoreFunction(plainText, 0, Cipher.ENCRYPT_MODE, (Key)key);
	}

	public byte[] RSADecrypt(byte[] cipherText, PrivateKey key) 
	{
		return EngineCoreFunction(cipherText, 0, Cipher.DECRYPT_MODE, (Key)key);
	}

	//performs encryption and decryption for all methods
	public byte[] EngineCoreFunction(byte[] bytes, int type, int mode, Key key) 
	{
		//throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, NoSuchProviderException, InvalidAlgorithmParameterException
		Cipher cipher = null;
		
		try
		{
			//RSA or AES
			if(type == 0)
			{
				cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(mode, key);
			}
			else
			{
				cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
				cipher.init(mode, key, IV);
			}
			return cipher.doFinal(bytes);
		}
		catch(NoSuchAlgorithmException e){System.out.println("CRYPTO ENGINE ERROR:  EngineCoreFunction;  No Such Algorithm");}
		catch(NoSuchPaddingException e){System.out.println("CRYPTO ENGINE ERROR:  EngineCoreFunction;  No Such Padding");}
		catch(InvalidKeyException e){System.out.println("CRYPTO ENGINE ERROR:  EngineCoreFunction;  Invalid Key");}
		catch(IllegalBlockSizeException e){System.out.println("CRYPTO ENGINE ERROR:  EngineCoreFunction;  Illegal Block Size");}
		catch(BadPaddingException e){System.out.println("CRYPTO ENGINE ERROR:  EngineCoreFunction;  Bad Padding");}
		catch(NoSuchProviderException e){System.out.println("CRYPTO ENGINE ERROR:  EngineCoreFunction;  No Such Provider");}
		catch(InvalidAlgorithmParameterException e)	{System.out.println("CRYPTO ENGINE ERROR:  EngineCoreFunction;  Invalid Algorithm Parameter");}

		return 	null;
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

	public byte[] StrToByte( String input) throws UnsupportedEncodingException
	{
		return input.getBytes("ISO-8859-1");
	}
}

