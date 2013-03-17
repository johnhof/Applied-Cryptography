/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.List;
import java.io.ObjectInputStream;
import java.security.*;
import javax.crypto.*;
import java.io.*;

public class GroupClient extends Client implements GroupClientInterface {
 	
	public boolean connect(final String server, final int port)
	{
		System.out.println("\n*** Attempting to connect to Group Server: NAME: " + server + "; PORT:" + port + " ***");
		super.connect(server, port);

		boolean keyNeedsSet = true;
		
		setKey();
		assert aesKey != null;

		System.out.println("\n*** Group Server connection successful: NAME: " + serverName + "; PORT:" + serverPort + " ***");
		return true;
	}
	
	public void disconnect()	 
	{
		if (isConnected()) 
		{
			try
			{
				Envelope message = new Envelope("DISCONNECT");
				System.out.println("\nGroup Server Request Sent: DISCONNECT");
				writeEncrypted(message);
				sock.close();//I don't see why we shouldn't attempt 
				//to close the socket on both the server and client sides

				System.out.println("\n*** Group Server disconnect successful: NAME: " + serverName + "; PORT:" + serverPort + " ***");
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
	
	
	private boolean setKey() 
	{
		try
		{
			Envelope message, response;
			message = new Envelope("PUBKEYREQ");//requests the servers public key
			System.out.println("\nGroup Server Request Sent: PUBKEYREQ");
			writePlainText(message);
			response = (Envelope)readPlainText();

			aesKey = cEngine.genAESKeySet();
			
			
			if(response.getMessage().equals("PUBKEYANSW"))
			{
				Key rsaPublic = (Key)response.getObjContents().get(0);
				System.out.println(cEngine.formatAsSuccess("public key obtained"));
				//encrypt the aesKey with the rsaPublic
				
				ByteArrayOutputStream toBytes = new ByteArrayOutputStream();//create ByteArrayOutputStream
				ObjectOutputStream localOutput = new ObjectOutputStream(toBytes);//Make an object outputstream to that bytestream
				
				localOutput.writeObject(aesKey.getKey());//write to the bytearrayoutputstream
				
				byte[] aesKeyBytes = toBytes.toByteArray();
				
				byte[] aesKeyBytesA = new byte[100];
				byte[] aesKeyBytesB = new byte[41];
				
				System.arraycopy(aesKeyBytes, 0, aesKeyBytesA, 0, 100);
				System.arraycopy(aesKeyBytes, 100, aesKeyBytesB, 0, 41);
				
				byte[] encryptedKeyA = cEngine.RSAEncrypt(aesKeyBytesA, rsaPublic);
				byte[] encryptedKeyB = cEngine.RSAEncrypt(aesKeyBytesB, rsaPublic);
				
				byte[] encryptedKey = new byte[encryptedKeyA.length + encryptedKeyB.length];
				System.arraycopy(encryptedKeyA, 0, encryptedKey, 0, 128);
				System.arraycopy(encryptedKeyB, 0, encryptedKey, 128, 128);
				
				message = new Envelope("AESKEY");
				message.addObject(encryptedKey);
				message.addObject(aesKey.getIV().getIV());
				
				System.out.println("\nGroup Server Request Sent: AESKEY");
				writePlainText(message);
				
				message = new Envelope("CHALLENGE");
				Integer challenge = new Integer((new SecureRandom()).nextInt());
				message.addObject(challenge);
				System.out.println("\nGroup Server Request Sent: CHALLENGE");
				writeEncrypted(message);
				
				response = (Envelope)readEncrypted();
				if(response.getMessage().equals("OK"))
				{
					if((challenge.intValue()+1) != ((Integer)response.getObjContents().get(0)).intValue())
					{
						System.out.println(cEngine.formatAsError("Challenge failed"));
						System.exit(-1);
					}
					else
					{
						System.out.println(cEngine.formatAsSuccess("Challenge passed"));
						return true;
					}
				}
			}
			else return false;
		}
		catch(Exception e)
		{
			e.printStackTrace();
			System.exit(-1);
		}
		return false;
	}
	
	public UserToken getToken(String username, String pwd)
	{
		try
		{
			UserToken token = null;
			Envelope message = null, response = null;	 	

			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(username); //Add user name string
			message.addObject(pwd);
			System.out.println("\nGroup Server Request Sent: GET");
			
			writeEncrypted(message);
			
			//Get the response from the server
			response = (Envelope)readEncrypted();
			
			//Successful response
			if(response.getMessage().equals("OK"))
			{
				//If there is a token in the Envelope, return it 
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				
				if(temp.size() == 1)
				{
					token = (UserToken)temp.get(0);
					System.out.println("\n*** Token obtained ***");
					return token;
				}
			}
			else
			{
				System.out.println(response.getMessage());
			}
			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
		
	 }
	 
	 public boolean createUser(String username, String pwd, UserToken token)
	 {
		try
		{
			Envelope message = null, response = null;

			//Tell the server to create a user
			message = new Envelope("CUSER");
			message.addObject(username); //Add user name string
			message.addObject(token); //Add the requester's token
			message.addObject(pwd);//add the desired password
			System.out.println("\nGroup Server Request Sent: CUSER");
			writeEncrypted(message);
			
			//response = (Envelope)readPlainText();
			response = (Envelope)readEncrypted();	
			//If server indicates success, return true
			if(response.getMessage().equals("OK"))
			{
				return true;
			}
				
			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	 }
	 
	 public boolean deleteUser(String username, UserToken token)
	 {
		try
		{
			Envelope message = null, response = null;
			 
			//Tell the server to delete a user
			message = new Envelope("DUSER");
			message.addObject(username); //Add user name
			message.addObject(token);  //Add requester's token
			System.out.println("\nGroup Server Request Sent: DUSER");
			writeEncrypted(message);
			
			//response = (Envelope)readPlainText();
			response = (Envelope)readEncrypted();		
			//If server indicates success, return true
			if(response.getMessage().equals("OK"))
			{
				return true;
			}
				
			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	 }
	 
	 public boolean createGroup(String groupname, UserToken token)
	 {
		try
		{
			Envelope message = null, response = null;
			//Tell the server to create a group
			message = new Envelope("CGROUP");
			message.addObject(groupname); //Add the group name string
			message.addObject(token); //Add the requester's token
			System.out.println("\nGroup Server Request Sent: CGROUP");
			writeEncrypted(message);
			
			//response = (Envelope)readPlainText();
			response = (Envelope)readEncrypted();		
			//If server indicates success, return true
			if(response.getMessage().equals("OK"))
			{
				return true;
			}
				
			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	 }
	 
	 public boolean deleteGroup(String groupname, UserToken token)
	 {
		try
		{
			Envelope message = null, response = null;
			//Tell the server to delete a group
			message = new Envelope("DGROUP");
			message.addObject(groupname); //Add group name string
			message.addObject(token); //Add requester's token
			System.out.println("\nGroup Server Request Sent: DGROUP");
			writeEncrypted(message);
			
			//response = (Envelope)readPlainText();
			response = (Envelope)readEncrypted();	
			//If server indicates success, return true
			if(response.getMessage().equals("OK"))
			{
				return true;
			}
			else System.out.println(response.getMessage());
			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	 }
	 
	 @SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token)
	 {
		try
		{
			Envelope message = null, response = null;
			//Tell the server to return the member list
			message = new Envelope("LMEMBERS");
			message.addObject(group); //Add group name string
			message.addObject(token); //Add requester's token
			System.out.println("\nGroup Server Request Sent: LMEMBERS");
			writeEncrypted(message);
			
			//response = (Envelope)readPlainText();
			response = (Envelope)readEncrypted();	
			//If server indicates success, return the member list
			if(response.getMessage().equals("OK"))
			{ 
				return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			}
				
			return null; 
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}
	 
	public boolean addUserToGroup(String username, String groupname, UserToken token)
	{
		try
		{
			Envelope message = null, response = null;
			//Tell the server to add a user to the group
			message = new Envelope("AUSERTOGROUP");
			message.addObject(username); //Add user name string
			message.addObject(groupname); //Add group name string
			message.addObject(token); //Add requester's token
			System.out.println("\nGroup Server Request Sent: AUSERTOGROUP");
			writeEncrypted(message);
			
			//response = (Envelope)readPlainText();
			response = (Envelope)readEncrypted();	
			//If server indicates success, return true
			
			if(response.getMessage().equals("OK"))
			{
				return true;
			}
				
			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}
	 
	public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
	{
		try
		{
			Envelope message = null, response = null;
			//Tell the server to remove a user from the group
			message = new Envelope("RUSERFROMGROUP");
			message.addObject(username); //Add user name string
			message.addObject(groupname); //Add group name string
			message.addObject(token); //Add requester's token
			System.out.println("\nGroup Server Request Sent: RUSERFROM GROUP");
			writeEncrypted(message);
			
			//response = (Envelope)readPlainText();
			response = (Envelope)readEncrypted();	
			//If server indicates success, return true
			if(response.getMessage().equals("OK"))
			{
				return true;
			}
			
			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public ArrayList<String> allUsers(UserToken token)
	{
		try
		{
			Envelope message = null, response = null;
			message = new Envelope("ALLUSERS");
			message.addObject(token); //Add user's token
			System.out.println("\nGroup Server Request Sent: ALLUSERS");
			writeEncrypted(message);
			
			//response = (Envelope)readPlainText();
			response = (Envelope)readEncrypted();	
			if(response.getMessage().equals("OK") && response.getObjContents() != null)
			{
				return (ArrayList<String>)response.getObjContents().get(0);
			}
			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}
}
