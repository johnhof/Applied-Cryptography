import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.util.*;
import java.lang.*;

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
			RSAKeyGen.initialize(2048);
		} 
		catch (NoSuchAlgorithmException e) {
			System.out.println("WARNING:  CRYPTOENGINE;  RSA key genrator initialization failure");
		}

  		//set up AES objects
        try {
			AESKeyGen = KeyGenerator.getInstance("AES", "BC");
			AESKeyGen.init(128);
		} 
		catch (Exception e) {
			System.out.println("WARNING:  CRYPTOENGINE;  AES key generator initialization failure");
		}
	}

//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-- HASH FUNCTIONS
//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	
	// Matt ~ 2013 2 April
	public String hashWithSHA(String input) throws NoSuchAlgorithmException
	{
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		return new String(input.getBytes()); 
	}
	
	
	public byte[] hashString(String str)
	{
		MessageDigest md = null;
		try
		{
			md = MessageDigest.getInstance("SHA");
		}
		catch(Exception e)
		{
			System.out.println("WARNING: Could not hash password");
			e.printStackTrace();
		}
		return md.digest(str.getBytes());
	}
	
	
//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-- KEY GENERATORS
//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

	public AESKeySet genAESKeySet()
	{
		//gent a key, IV pair and return it
	    return new AESKeySet(AESKeyGen.generateKey(), new IvParameterSpec(new byte[16]));
	}
	public KeyPair genRSAKeyPair()
	{
		KeyPair keys = null;
		try
		{
			keys = RSAKeyGen.generateKeyPair();
		}
		catch(Exception e)
		{
			System.out.println("WARNING:  CRYPTOENGINE;  RSAS key gen failure");
			return null;
		}
  		return keys;
	}

//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-- SIGNING AND VERIFICATION 
//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

	//return the signature as a byte array
	public byte[] RSASign(byte[] plainText, PrivateKey key) 
	{
  	    Signature signature;
  	    byte[] sigBytes = null;
		try 
		{
			signature = Signature.getInstance("SHA1withRSA", "BC");
			signature.initSign(key, new SecureRandom()); 
			signature.update(plainText);
			sigBytes = signature.sign();
		} 
		catch (Exception e) 
		{
			System.out.println("WARNING:  CRYPTOENGINE;  RSA sign failure");
		}
		return sigBytes;
	}

	//return boolean of verified signature in byte form
	public boolean RSAVerify(byte[] plainText, byte[] sigBytes, PublicKey key) 
	{
		boolean verified = false;
	  	Signature signature;
		try 
		{
			signature = Signature.getInstance("SHA1withRSA", "BC");
		    signature.initVerify(key);
			signature.update(plainText);
		    verified = signature.verify(sigBytes);
		} 
		catch (Exception e) 
		{
			System.out.println("WARNING:  CRYPTOENGINE;  RSA signature verification failure");
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
	//performs encryption and decryption for AES
	private byte[] DriverCoreFunction(byte[] bytes, int mode, AESKeySet keySet) 
	{
		Cipher cipher = null;
		byte[]result = null;
		Key key = keySet.getKey();
		IvParameterSpec IV = keySet.getIV();

		try 
		{
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			cipher.init(mode, key, IV);
			result = cipher.doFinal(bytes);	
		} 
		catch (Exception e) {
			//System.out.println("WARNING:  CRYPTOENGINE;  AES cipher failure; encrypt(1)/decrypt(2)="+mode);
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
	private byte[] DriverCoreFunction(byte[] bytes,  int mode, Key key) 
	{
		byte[]result = null;
		try 
		{
			//perform encryption
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(mode, key);	
			result = cipher.doFinal(bytes);
		} 
		catch (Exception e) 
		{
			//System.out.println("WARNING:  CRYPTOENGINE;  RSA cipher failure;  encrypt(1)/decrypt(2)="+mode);
		}
		return result;
	}
	
//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-- EXTERNAL UTILITY FUNCTIONS
//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

	//string specific serializers/deserializers
	public String byteToStr(byte[] input)
	{
	    byte[] output = new byte[input.length];
	    int i = 0;

	    for (Byte current : input) 
	    {
	        output[i] = current;
	        i++;
	    }

		return new String(output,  Charset.forName("ISO-8859-1"));	
	}

	public byte[] strToByte( String input) 
	{
		try 
		{
			return input.getBytes("ISO-8859-1");
		} 
		catch (UnsupportedEncodingException e) 
		{
			System.out.println("WARNING:  CRYPTOENGINE;  string to byte conversion failure");
			return null;
		}
	}

	//general purpose serializer
    public byte[] serialize(Object obj)
    {
    	byte[] byteArray = null;
    	try
    	{
        	ByteArrayOutputStream bStream = new ByteArrayOutputStream();
        	ObjectOutputStream oStream = new ObjectOutputStream(bStream);
        	oStream.writeObject(obj);
        	byteArray = bStream.toByteArray();
		}
        catch(Exception e)
        {
			System.out.println("WARNING:  CRYPTOENGINE;  serializing error, NULL returned");
			e.printStackTrace();
        	return null;
        }
        return byteArray;
    }

	//general purpose deserializer
    public Object deserialize(byte[] bytes)
    {
    	Object obj = null;
    	try
    	{
	        ByteArrayInputStream bStream = new ByteArrayInputStream(bytes);
	        ObjectInputStream oStream = new ObjectInputStream(bStream);
	        obj = oStream.readObject();
		}
        catch(Exception e)
        {
        	return null;
        }
        return obj;
    }

    public String formatAsError(String input)
    {
    	return ("     !"+input);
    }

    public static String formatAsSuccess(String input)
    {
    	return ("     *"+input);
    }

//----------------------------------------------------------------------------------------------------------------------
//-- COMMUNICATION FUNCITONS
//----------------------------------------------------------------------------------------------------------------------

	protected boolean writePlainText(Object obj, ObjectOutputStream output)
	{
		try
		{
			output.writeObject(obj);
			return true;
		}
		catch(Exception e)
		{
			System.out.println(formatAsError("IO/ClassNotFound Exception when writing (Unencrypted) data"));
		}
		return false;
	}
	protected boolean writeAESEncrypted(Object obj, AESKeySet key, ObjectOutputStream output)
	{
		try
		{
			byte[] eData = AESEncrypt(serialize(obj), key);//encrypt the data
			
			System.out.println(formatAsSuccess("AES encryption successful"));

			output.writeObject(eData);//write the data to the client
			return true;
		}
		catch(Exception e)
		{
			System.out.println(formatAsError("IO/ClassNotFound Exception when writing (Encrypted) data"));
		}
		return false;
	}
	protected boolean writeRSAEncrypted(Object obj, Key key, ObjectOutputStream output)
	{
		try
		{
			byte[] eData = RSAEncrypt(serialize(obj), key);//encrypt the data
			
			System.out.println(formatAsSuccess("RSA encryption successful"));

			output.writeObject(eData);//write the data to the client
			return true;
		}
		catch(Exception e)
		{
			System.out.println(formatAsError("IO/ClassNotFound Exception when writing (Encrypted) data"));
		}
		return false;
	}
	
	protected Object readPlainText(ObjectInputStream input)
	{
		try
		{
			return input.readObject();
		}
		catch(Exception e)
		{
			System.out.println(formatAsError("IO/ClassNotFound Exception when reading (Unencrypted) data"));
		}
		return null;
	}
	protected Object readAESEncrypted(AESKeySet key, ObjectInputStream input)
	{
		try
		{
			byte[] data = AESDecrypt((byte[])input.readObject(), key);

			System.out.println(formatAsSuccess("AES decryption successful"));

			return deserialize(data);
		}
		catch(Exception e)
		{
			System.out.println(formatAsError("IO/ClassNotFound Exception when reading (Encrypted) data"));
		}
		return null;
	}
	protected Object readRSAEncrypted(Key key, ObjectInputStream input)
	{
		try
		{
			byte[] data = RSADecrypt((byte[])input.readObject(), key);

			System.out.println(formatAsSuccess("RSA decryption successful"));

			return deserialize(data);
		}
		catch(Exception e)
		{
			System.out.println(formatAsError("IO/ClassNotFound Exception when reading (Encrypted) data"));
		}
		return null;
	}

//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-- HMAC FUNCTIONS
//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

	public SecretKeySpec genHMACKey()
	{
		//should this be random? -john 4/3
		return new SecretKeySpec("qnscAdgRlkIhAUPY44oiexBKtQbGY0orf7OV1I50".getBytes(), "HmacSHA1");
	}

	public boolean checkHMAC(Envelope message, SecretKeySpec keySpec)
	{
		//TODO: -HMAC- : get the last object of the message, and assume its the HMAC
		//				compute the HMAC using the preceding contents of the message
		//				return whether or not the message is untampered
		if(((String)message.getObjContents().get((message.getObjContents().size()-1))).equals("HMAC"))
		{
			System.out.println(formatAsSuccess("HMAC valid"));
		}
		else
		{
			System.out.println(formatAsError("HMAC invalid"));
			return false;
		}
		return true;
	}

	public Envelope attachHMAC(Envelope message, SecretKeySpec keySpec)
	{
		//TODO: -HMAC- : given a message, compute the HMAC on its contents, and add an
		//				HMAC object to the end of the message
		message.addObject("HMAC");
		System.out.println(formatAsSuccess("HMAC computed and added"));
		return message;
	}
}

