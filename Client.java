import java.net.Socket;
import java.io.*;

public class Client extends ClientInterface
{
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;

	public boolean connect(final String server, final int port) 
	{
		System.out.print("Attempting to connect... ");

//my attempt starts here
		try
		{
			//create socket
			sock = new Socket(server, port);
			System.out.println("Connected to "+server+" in port "+port);

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
				output.writeObject(message);
				sock.close();//I don't see why we shouldn't attempt 
				//to close the socket on both the server and client sides
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
}
