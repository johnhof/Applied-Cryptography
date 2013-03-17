import java.net.Socket;
import java.io.*;

public class Client extends ClientInterface
{
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;
	protected CryptoEngine cEngine;
	protected AESKeySet aesKey;

	//NOTE: I removed the feedback from this since it's called by its subclasses, object specific feedback is printed there - john, 3/16
		//I just noticed that this probably the most famous bible verse. your move athiests 
	public boolean connect(final String server, final int port) 
	{
		serverName = server;
		serverPort = port;

		cEngine = new CryptoEngine();	

		//my attempt starts here
		try
		{
			//create socket
			sock = new Socket(server, port);

			//i/o streams
			output = new ObjectOutputStream(sock.getOutputStream());
			output.flush();
			input = new ObjectInputStream(sock.getInputStream());
		}
		catch(IOException e)
		{
			e.printStackTrace();
		}
		catch(Exception e) // UnknownHostException refused to be found, no matter what I imported...?
		{
			System.err.println("Host unknown: "+e.toString());
		}
		
		
		return true;
	}

	public boolean isConnected() 
	{
		if (sock == null || !sock.isConnected()) 
		{
			return false;
		}
		else 
		{
			return true;
		}
	}

	public void disconnect()	 
	{
		if (isConnected()) 
		{
			try
			{
				Envelope message = new Envelope("DISCONNECT");
				System.out.println("\nRequest Sent: DISCONNECT");
				output.writeObject(message);
				sock.close();//I don't see why we shouldn't attempt 
				//to close the socket on both the server and client sides

				System.out.println("\n*** Server disconnect successful: NAME: " + serverName + "; PORT:" + serverPort + " ***");
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}

	protected boolean writePlainText(Object obj)
	{
		try
		{
			output.writeObject(obj);
			System.out.println(cEngine.formatAsSuccess("Message sent in plaintext"));
			return true;
		}
		catch(Exception e)
		{
			System.out.println(cEngine.formatAsError("IO/ClassNotFound Exception when writing (Unencrypted) data"));
		}
		return false;
	}
	protected boolean writeEncrypted(Object obj)
	{
		try
		{
			byte[] eData = cEngine.AESEncrypt(cEngine.serialize(obj), aesKey);//encrypt the data
			
			System.out.println(cEngine.formatAsSuccess("AES encryption successful"));

			output.writeObject(eData);//write the data to the client
			return true;
		}
		catch(Exception e)
		{
			System.out.println(cEngine.formatAsError("IO/ClassNotFound Exception when writing (Encrypted) data"));
		}
		return false;
	}
	
	protected Object readPlainText()
	{
		try
		{
			System.out.println(cEngine.formatAsSuccess("Message recieved in plaintext"));
			return input.readObject();
		}
		catch(Exception e)
		{
			System.out.println(cEngine.formatAsError("IO/ClassNotFound Exception when reading (Unencrypted) data"));
		}
		return null;
	}
	protected Object readEncrypted()
	{
		try
		{
			byte[] data = cEngine.AESDecrypt((byte[])input.readObject(), aesKey);

			System.out.println(cEngine.formatAsSuccess("AES decryption successful"));

			return cEngine.deserialize(data);
		}
		catch(Exception e)
		{
			System.out.println(cEngine.formatAsError("IO/ClassNotFound Exception when reading (Encrypted) data"));
		}
		return null;
	}
}
