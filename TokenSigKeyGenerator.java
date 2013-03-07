
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

import java.io.*;

//import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.util.List;

public class TokenSigKeyGenerator
{
    public static void main (String[] args)
    {
		String resourceFile = "GroupResources"+System.getProperty("path.separator")+"GroupResources.bin";
		String keyDisrtoFile = "GroupPublicResources"+System.getProperty("path.separator")+"GroupPublicKey.bin";
		ObjectOutputStream outStream;
	    InputStreamReader reader = new InputStreamReader(System.in);
	    BufferedReader in = new BufferedReader(reader);

		try
		{
			System.out.println("\nAre you sure you want to overwrite old groupserver signing keys? [y/n] ");
			if(!in.readLine().equals("y"))
			{
				System.out.println("action canceled; old files preserved");
				return; 	
			} 
		}
		catch(Exception e)
		{
			System.out.println("IO Error");
			return;
		}

		//gen keys
	    CryptoEngine cEngine = new CryptoEngine();
		KeyPair keys = cEngine.genRSAKeyPair();
		PublicKey pkey = keys.getPublic();

		//save keys
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream(resourceFile));
			outStream.writeObject(keys);

			outStream = new ObjectOutputStream(new FileOutputStream(keyDisrtoFile));
			outStream.writeObject(pkey);	
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		
		System.out.println("Finished generating keys:\nPrivate: "+keys.getPrivate().toString()+"\nPublic"+keys.getPublic().toString());
    }

}