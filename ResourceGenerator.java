
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import java.io.*;

//import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.util.List;

public class ResourceGenerator
{
    public static void main (String[] args)
    {
    	String publicFolder = "Public_Resources";
    	String groupFolder = "Group_Server_Resources";
		String resourceFile = "GroupResources.bin";
		String keyDisrtoFile = "GroupPublicKey.bin";
		ObjectOutputStream outStream;
	    InputStreamReader reader = new InputStreamReader(System.in);
	    BufferedReader in = new BufferedReader(reader);
/*
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
		}*/

	    //create the folders
		File file = new File(publicFolder);
		file.mkdir();

		file = new File(groupFolder);
		file.mkdir();

		//gen keys
	    CryptoEngine cEngine = new CryptoEngine();
		KeyPair keys = cEngine.genRSAKeyPair();
		PublicKey pkey = keys.getPublic();

		//save keys
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream(groupFolder+"/"+resourceFile));
			outStream.writeObject(keys);

			outStream = new ObjectOutputStream(new FileOutputStream(publicFolder+"/"+keyDisrtoFile));
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