/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

//import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;
public class FileServer extends Server 
{
	
	//IMPORTANT: server listens on port 4321
	public static final int SERVER_PORT = 4321;
	public static FileList fileList;
	public static PublicKey signVerifyKey;
	public KeyPair authKeys;
	public CryptoEngine cEngine;
	
	public FileServer() 
	{
		super(SERVER_PORT, "FilePile");
		cEngine = new CryptoEngine();
	}

	public FileServer(int _port) 
	{
		super(_port, "FilePile");
		cEngine = new CryptoEngine();
	}
	
	public void start() 
	{
		String fileFile = "FileList.bin";
        String keyDistroFile = "GroupPublicKey.bin";
		ObjectInputStream fileStream;
		ObjectInputStream sigKeyStream;
		
		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerFS(this));
		runtime.addShutdownHook(catchExit);
		
//----------------------------------------------------------------------------------------------------------------------
//--ADDED: retrieve the group server public key to verify signatures
//----------------------------------------------------------------------------------------------------------------------
		try
		{
			FileInputStream fis = new FileInputStream(keyDistroFile);
			sigKeyStream = new ObjectInputStream(fis);

			//retrieve the keys used for signing
			signVerifyKey = (PublicKey)sigKeyStream.readObject();
		}
		catch(Exception e)
		{
			System.out.println("ERROR:  FILESERVER;  could not load resource file");
			System.exit(-1);
		}
//----------------------------------------------------------------------------------------------------------------------
		try
		{
			authKeys = cEngine.genRSAKeyPair();
		}
		catch(Exception e)
		{
			System.out.println("ERROR:FILESERVER; could not generate RSA Key Pair");
			System.exit(-1);
		}
		
		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(fileFile);
			fileStream = new ObjectInputStream(fis);
			fileList = (FileList)fileStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("FileList Does Not Exist. Creating FileList...");
			fileList = new FileList();
		}
		catch(IOException e)
		{
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}
		
		//Create or find a directory named "shared_files"
		File file = new File("shared_files");
		if (file.mkdir()) 
		{
			System.out.println("Created new shared_files directory");
		}
		else if (file.exists())
		{
			System.out.println("Found shared_files directory");
		}
		else 
		{
			System.out.println("Error creating shared_files directory");				 
		}
		
		//Autosave Daemon. Saves lists every 5 minutes
		AutoSaveFS aSave = new AutoSaveFS(this);
		aSave.setDaemon(true);
		aSave.start();
		
		boolean running = true;
		
		//setup the socket
		try
		{			
			final ServerSocket serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());
			
			Socket sock = null;
			Thread thread = null;
			
			//spawn a thread to listen on the socket
			while(running)
			{
				sock = serverSock.accept();
				//THREAD HANDLES CORE FUNCTIONALITY. SEE FileThread.java
				thread = new FileThread(this, sock);
				thread.start();
			}
			
			//if we reach this, the socket has closed
			System.out.printf("%s shut down\n", this.getClass().getName());
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}

		System.out.println("\nUPDATE: GroupServer; setup succesful");
	}
}

//This thread saves user and group lists
class ShutDownListenerFS implements Runnable
{
	public FileServer my_fs;
	
	public ShutDownListenerFS (FileServer _fs) 
	{
		my_fs = _fs;
	}

	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;

		//write the filelist to FileList.bin
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
			outStream.writeObject(FileServer.fileList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSaveFS extends Thread
{
	public FileServer my_fs;
	
	public AutoSaveFS (FileServer _fs) 
	{
		my_fs = _fs;
	}

	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave file list...");
				ObjectOutputStream outStream;

				//write the filelist to FileList.bin
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
					outStream.writeObject(FileServer.fileList);
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}

			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		}
		while(true);
	}
}
