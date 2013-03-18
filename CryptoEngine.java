import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;

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
			System.out.println("WARNING:  CRYPTOENGINE;  RSA key genrator initialization failure");
		}

  		//set up AES objects
        try {
			AESKeyGen = KeyGenerator.getInstance("AES", "BC");
			AESKeyGen.init(128);
		} 
		catch (Exception e) {
			System.out.println("WARNING:  CRYPTOENGINE;  AES key genrator initialization failure");
		}
	}

//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-- HASH FUNCTIONS
//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	
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
			result = cipher.doFinal(bytes);	
		} 
		catch (Exception e) {
			System.out.println("WARNING:  CRYPTOENGINE;  AES cipher failure; encrypt(1)/decrypt(2)="+mode);
			e.printStackTrace();
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
		byte[]encryptedChunk = null;
		int inputSize = bytes.length;
		int byteIndex;

		try 
		{
			//en/decrypt in 128 byte chunks
			for(byteIndex = 128; byteIndex < inputSize; byteIndex+=128)
			{
				cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(mode, key);	

				//get the encrypted chunk and append it to the result
				encryptedChunk = cipher.doFinal(Arrays.copyOfRange(bytes, byteIndex-128, byteIndex));

				//backup the existing array
				byte[] temp = new byte[result.length];
				System.arraycopy(result, 0,  temp, 0, result.length);	

				//resize and append to the result array
				result = new byte[temp.length+encryptedChunk.length];
				System.arraycopy(temp, 0,  result, 0, temp.length);	
				System.arraycopy(encryptedChunk, 0,  result, 0, encryptedChunk.length);	
			}
			//en/decrypt the last junk
			if(byteIndex>inputSize)
			{
				cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(mode, key);	

				//get the encrypted chunk and append it to the result
				encryptedChunk = cipher.doFinal(Arrays.copyOfRange(bytes, byteIndex-128, byteIndex));

				//backup the existing array
				byte[] temp = new byte[result.length];
				System.arraycopy(result, 0,  temp, 0, result.length);	

				//resize and append to the result array
				result = new byte[temp.length+encryptedChunk.length];
				System.arraycopy(temp, 0,  result, 0, temp.length);	
				System.arraycopy(encryptedChunk, 0,  result, 0, encryptedChunk.length);	
			}
		} 
		catch (Exception e) 
		{
			System.out.println("WARNING:  CRYPTOENGINE;  RSA cipher failure;  encrypt(1)/decrypt(2)="+mode);
			e.printStackTrace();
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
			System.out.println("WARNING:  CRYPTOENGINE;  deserializing error, NULL returned");
        	return null;
        }
        return obj;
    }

    public String formatAsError(String input)
    {
    	return ("     !"+input);
    }

    public String formatAsSuccess(String input)
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
}

