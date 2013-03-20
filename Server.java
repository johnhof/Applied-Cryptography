
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
	public String name;
	abstract void start();
	public KeyPair authKeys;
	public CryptoEngine cEngine;
	
	public Server(int _SERVER_PORT, String _serverName) 
	{
		port = _SERVER_PORT;
		name = _serverName; 

		System.out.println("NAME: "+name+";    PORT: "+port);

    	cEngine = new CryptoEngine();		
    	try
		{
			authKeys = cEngine.genRSAKeyPair();
		}
		catch(Exception e)
		{
			System.out.println("ERROR:FILESERVER; could not generate RSA Key Pair");
			System.exit(-1);
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
