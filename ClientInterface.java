import java.net.Socket;
import java.io.*;

public abstract class ClientInterface
{

	/* protected keyword is like private but subclasses have access
	 * Socket and input/output streams
	 */
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;
	protected String serverName;
	protected int serverPort;

	public boolean connect(final String server, final int port) 
	{

		serverName = server;
		serverPort = port;

		System.out.println("attempting to connect");
				System.out.println("\n!!!THIS SHOULD NEVER RUN. WHY WAN'T THIS OVERWRITTEN???!!!");

		/* TODO: Write this method */
		return false;
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
				System.out.println("\nRequest Sent: DISCONNECT");//this line is really just here for consistency
				output.writeObject(message);
				System.out.println("\n*** Server disconnect successful: NAME: " + serverName + "; PORT:" + serverPort + " ***");
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
}
