/* FileServer loads files from FileList.rsc.  Stores files in shared_files directory. */

import java.nio.charset.Charset;
import java.security.*;
import javax.crypto.*;
import java.net.*;
import java.io.*;
import java.util.*;

//import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class FileServer extends Server 
{
	
	//IMPORTANT: server listens on port 7777
	public static final int SERVER_PORT = 7777;
	public static FileList fileList;
	public static PublicKey signVerifyKey;
	
	public FileServer() 
	{
		//pass in the server type to create the appropriate directory
		super(SERVER_PORT, "FilePile", "File");
	}

	public FileServer(int _port) 
	{
		//pass in the server type to create the appropriate directory
		super(_port, "FilePile", "File");
	}
	
	public void start() 
	{		
    	String publicFolder = "Public_Resources/";

		//open the resource folder, remove it if it had to be generated
		File file = new File(publicFolder);
		if(file.mkdir())
		{
            file.delete();
			System.out.println("\nResourceGenerator must be run before continuing\n");
			return;
		}

		System.out.println("\nSetting up resources");

		String fileFile = resourceFolder+"FileList.rsc";
        String keyDistroFile = "GroupPublicKey.rsc";
		ObjectInputStream fileStream;
		ObjectInputStream sigKeyStream;
		
		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerFS(this));
		runtime.addShutdownHook(catchExit);

		//set up the authentication key
		if(!setAuthKey()) System.exit(-1);

//--RETRIEVE THE TOKEN VERIFIER-----------------------------------------------------------------------------------------
		
		try
		{
			System.out.println("\nTrying to access GroupPublicKey File");
			FileInputStream fis = new FileInputStream(publicFolder+keyDistroFile);
			sigKeyStream = new ObjectInputStream(fis);
			signVerifyKey = (PublicKey)sigKeyStream.readObject();
			System.out.println(cEngine.formatAsSuccess("Token verifier recovered"));	
		}
		catch(Exception e)
		{
			System.out.println("\nERROR:  FILESERVER;  could not load resource file");
			System.exit(-1);
		}

//--GET THE FILE LIST---------------------------------------------------------------------------------------------------
		
		//Open file file to get user list
		try
		{
			System.out.println("\nTrying to access FileList File");
			FileInputStream fis = new FileInputStream(fileFile);
			fileStream = new ObjectInputStream(fis);
			fileList = (FileList)fileStream.readObject();
			System.out.println(cEngine.formatAsSuccess("FileList recovered"));
		}
		catch(FileNotFoundException e)
		{
			System.out.println(cEngine.formatAsSuccess("FileList does not exist. Creating FileList"));
			fileList = new FileList();
		}
		catch(IOException e)
		{
			System.out.println(cEngine.formatAsError("Error reading from FileList file"));
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println(cEngine.formatAsError("Error reading from FileList file"));
			System.exit(-1);
		}
		
		//Create or find a directory named "shared_files"
		file = new File(resourceFolder+"shared_files");
		if (file.exists())
		{
			System.out.println(cEngine.formatAsSuccess("Found shared_files directory"));
		}
		else if (file.mkdir()) 
		{
			System.out.println(cEngine.formatAsSuccess("Created new shared_files directory"));
		} 
		else 
		{
			System.out.println(cEngine.formatAsError("Error creating shared_files directory"));				 
		}
	
//--SET UP SAVE DEMON---------------------------------------------------------------------------------------------------
	
		//Autosave Daemon. Saves lists every 5 minutes
		AutoSaveFS aSave = new AutoSaveFS(this);
		aSave.setDaemon(true);
		aSave.start();
		
		boolean running = true;	
		System.out.println("\nUPDATE: "+name+" File Server; setup succesful");

//--SET UP SOCKET LOOP--------------------------------------------------------------------------------------------------

		//setup the socket
		try
		{			
			final ServerSocket serverSock = new ServerSocket(port);
			
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
	}
}

//----------------------------------------------------------------------------------------------------------------------
//-- SAVING DEMONS
//----------------------------------------------------------------------------------------------------------------------

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
		System.out.println("Shutting down server...");

		ObjectOutputStream outStream;

		//write the filelist to FileList.rsc
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream(my_fs.getResourceFolder()+"FileList.rsc"));
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
				System.out.println("\nAutosave file list...");
				ObjectOutputStream outStream;

				//write the filelist to FileList.rsc
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream(my_fs.getResourceFolder()+"FileList.rsc"));
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
				System.out.println("\nAutosave Interrupted");
			}
		}
		while(true);
	}
}
