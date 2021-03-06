
import java.nio.charset.Charset;
import java.security.*;
import javax.crypto.*;
import java.net.*;
import java.io.*;
import java.util.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public abstract class Server 
{
	
	protected int port;
	protected String name;
	abstract void start();
	protected KeyPair authKeys;
	public CryptoEngine cEngine;
	public String resourceFolder;
	protected String fileExt;
	protected String authKeyFile;
	
	public Server(int _SERVER_PORT, String _serverName, String serverType) 
	{
		port = _SERVER_PORT;
		name = _serverName; 

		System.out.println("\n\n***********************************************************\n"+
								"****                    New Session                    ****\n"+
								"***********************************************************\n");

		System.out.println("\nNAME: "+name+";    PORT: "+port);

    	cEngine = new CryptoEngine();	

    	resourceFolder = name+"_"+serverType+"Server_Resources/";

		authKeyFile = "AuthKeys.rsc";
	}
	
	protected boolean setAuthKey()
	{
		try
		{
			System.out.println("\nTrying to access Authentication File");
			FileInputStream fis = new FileInputStream(resourceFolder+authKeyFile);
			ObjectInputStream resourceStream = new ObjectInputStream(fis);
			authKeys = (KeyPair)resourceStream.readObject();	
			System.out.println(cEngine.formatAsSuccess("Keys recovered"));		
			return true;
		}
		//if the authkey file doesnt exist, create it
		catch(FileNotFoundException ex)
		{
			System.out.println(cEngine.formatAsSuccess("Authentication File Does Not Exist. Creating keys"));

	    	try
			{
				authKeys = cEngine.genRSAKeyPair();
				boolean success = saveAuthKey();
				if(success)
				{
					return true;
				}
			}
			catch(Exception exc)
			{
				System.out.println("\nERROR: SERVER; could not generate RSA Key Pair");
				return false;
			}
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
		return false;
	}

	public String getResourceFolder()
	{
		return resourceFolder;
	}

	public boolean saveAuthKey()
	{
		try
		{
			File file = new File(resourceFolder);

			if (file.exists())
			{
				System.out.println(cEngine.formatAsSuccess("Found the server directory"));
			}
			else
			{
				System.out.println(cEngine.formatAsSuccess("Created the server directory"));
				file.mkdir();
			}

			ObjectOutputStream outStream = new ObjectOutputStream(new FileOutputStream(resourceFolder+authKeyFile));//save UserList
			outStream.writeObject(authKeys);
			return true;
		}
		catch(Exception exc)
		{
			System.out.println("\nERROR: SERVER; could not save authentication keys");
			return false;
		}

	}
		
	public int getPort() 
	{
		return port;
	}
	
	public String getName() 
	{
		return name;
	}

	public KeyPair getAuthKeys()
	{
		return authKeys;
	}

}
