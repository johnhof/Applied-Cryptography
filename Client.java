import java.net.*;
import java.security.*;
import javax.crypto.*;
import java.io.*;
import java.util.*;
import javax.crypto.spec.IvParameterSpec;

public class Client extends ClientInterface
{
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;
	protected CryptoEngine cEngine;
	protected AESKeySet aesKey;
	private KeyList keyList;
	protected String userName;
	protected String userFolder;
	protected String keyFile;
	private Key serverPublicKey;

	//group file key maps: HashMap<groupName, HashMap<keyID, AESKeySet>>
	protected HashMap<String, HashMap<String, AESKeySet>> groupFileKeyMap;

	public boolean connect(final String server, final int port, String username) 
	{
		serverName = server;
		serverPort = port;
		userName = username;
		userFolder = "User_Resources_"+userName+"/";
		keyFile = "ServerKeys.rsc";

		cEngine = new CryptoEngine();	


		//Create or locate the users directory"
		File file = new File(userFolder);
		if (file.exists())
		{
			System.out.println("\nFound user directory");
		}
		else if (file.mkdir()) 
		{
			System.out.println("\nCreated new user directory");
		} 
		else 
		{
			System.out.println("\nError creating user directory");				 
		}


		//my attempt starts here
		try
		{
			//create socket
			if(server.equals("ALPHA") || server.equals("FilePile")) sock = new Socket("localhost", port); //if the defaults were entered, use localhost
			else sock = new Socket(server, port);

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
				System.out.println("\n>> Sending Request: DISCONNECT");
				cEngine.writeAESEncrypted(message, aesKey, output);
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


//----------------------------------------------------------------------------------------------------------------------
//-- CONNECTION SETUP FUNCIONS
//----------------------------------------------------------------------------------------------------------------------

	protected boolean setUpServer(String server)
	{

//--ATHENTICATE SERVER--------------------------------------------------------------------------------------------------
		
		ObjectInputStream keyStream;
		
		System.out.println("\nSetting up resources");
		try
		{
			//Read in the key
			FileInputStream fis = new FileInputStream(userFolder+keyFile);
			keyStream = new ObjectInputStream(fis);
			keyList = (KeyList)keyStream.readObject();

			//If we have connected before
			if(keyList.checkServer(server))
			{
				//grab the public key
				serverPublicKey = keyList.getKey(server);
				System.out.println(cEngine.formatAsSuccess("This is a known server, no public key request necessary"));
			}
			//If its a new server
			else
			{
				System.out.println(cEngine.formatAsSuccess("This is not a known server, public key request necessary"));
				if(establishNewServer(server))
				{
					System.out.println(cEngine.formatAsSuccess("new server established"));
				}
				else
				{ 
					System.out.println(cEngine.formatAsError("Could not establish new server"));
					return false;
				}
			}
		}
		catch(FileNotFoundException exc)
		{
			System.out.println(cEngine.formatAsSuccess("KeyList does not exist. Creating it"));
			keyList = new KeyList();

			if(establishNewServer(server))
			{
				System.out.println(cEngine.formatAsSuccess("new server established, key file generated"));
			}
			else 
			{
				System.out.println(cEngine.formatAsError("Could not establish new server"));
				return false;
			}
		}
		catch(Exception exc)
		{
			System.out.println(cEngine.formatAsError("Expection thrown"));
			exc.printStackTrace();
			return false;
		}

//--SET SESSION KEY-------------------------------------------------------------------------------------------------
		try
		{
			Envelope message, response;

			//set AES key
			aesKey = cEngine.genAESKeySet();

			//generate the challenge
			Integer challenge = new Integer((new SecureRandom()).nextInt());

			//send the key to the server
			message = new Envelope("SET_AESKEY");
			System.out.println("\n>> Sending Request: SET_AESKEY");
			message.addObject(AESKeyToByte());
			message.addObject(aesKey.getIV().getIV());
			message.addObject(cEngine.RSAEncrypt(cEngine.serialize(challenge), serverPublicKey));
			System.out.println(cEngine.formatAsSuccess("RSA encryption successful, IV sent in plaintext"));
		
			cEngine.writePlainText(message, output);
			//THE AES KEY IS NOW SET

			System.out.println("<< Recieving Response: OK");
			response = (Envelope)cEngine.readAESEncrypted(aesKey, input);
			if(response.getMessage().equals("OK"))
			{
				if((challenge.intValue()+1) != ((Integer)response.getObjContents().get(0)).intValue())
				{
					System.out.println(cEngine.formatAsError("Challenge failed, server rejected"));
					return false;
				}
				else
				{
					System.out.println(cEngine.formatAsSuccess("Challenge passed, server authenticated"));
				}
			}
			else
			{
				System.out.println(cEngine.formatAsError("Unexpected response: "+response.getMessage()));
				return false;
			}
		}
		catch(Exception e)
		{
			System.out.println(cEngine.formatAsError("Server failed to authenticate"));
			return false;
		}
		return true;
	}

//----------------------------------------------------------------------------------------------------------------------
//-- UTILITY FUNCITONS
//----------------------------------------------------------------------------------------------------------------------

//--GET PUBLIC KEY---------------------------------------------------------------------------------------------------
	protected Key getPublicKey()
	{	
		Envelope message, response;
		Key answer = null;
		try
		{
			message = new Envelope("GET_PUBKEY");
			System.out.println("\n>> Sending Request: GET_PUBKEY");
			cEngine.writePlainText(message, output);
			response = (Envelope)cEngine.readPlainText(input);
			if(response.getMessage().equals("OK"))
			{
				System.out.println("<< Recieving Response: OK");
				answer = (Key)response.getObjContents().get(0);
				System.out.println(cEngine.formatAsSuccess("public key obtained"));
			}
		}
		catch(Exception e)
		{
			System.out.println("\nERROR: FILECLIENT: FAILED TO RECEIVE PUBLIC KEY");
			e.printStackTrace();
			return null;
		}
		return answer;
	}

//--CONVERT KEY TO BYTE ARRAY---------------------------------------------------------------------------------------------------
	protected byte[] AESKeyToByte()
	{
		try
		{
			ByteArrayOutputStream toBytes = new ByteArrayOutputStream();
			ObjectOutputStream localInput = new ObjectOutputStream(toBytes);

			localInput.writeObject(aesKey.getKey());

			byte[] aesKeyBytes = toBytes.toByteArray();

			byte[] aesKeyBytesA = new byte[100];
			byte[] aesKeyBytesB = new byte[41];

			System.arraycopy(aesKeyBytes, 0, aesKeyBytesA, 0, aesKeyBytesA.length);
			System.arraycopy(aesKeyBytes, 100, aesKeyBytesB, 0, aesKeyBytes.length-100);

			byte[] encryptedKeyA = cEngine.RSAEncrypt(aesKeyBytesA, serverPublicKey);
			byte[] encryptedKeyB = cEngine.RSAEncrypt(aesKeyBytesB, serverPublicKey);

			System.out.println(cEngine.formatAsSuccess("AES key encrypted with public key"));

			byte[] encryptedKey = new byte [encryptedKeyA.length + encryptedKeyB.length];

			System.arraycopy(encryptedKeyA, 0, encryptedKey, 0, encryptedKeyA.length);
			System.arraycopy(encryptedKeyB, 0, encryptedKey, encryptedKeyA.length, encryptedKeyB.length);

			return encryptedKey;
		}
		catch(Exception exc)
		{
			System.out.println("\nERROR: FILECLIENT; AES Key to enctrypted byte stream conversion failed");
			return null;
		}
	}

	protected boolean establishNewServer(String server)
	{
		//Retrieve the key
		serverPublicKey = getPublicKey();
		if(serverPublicKey == null)
		{
			System.out.println(cEngine.formatAsError("failed to retrieve public key"));
			return false;
		}
			
		//Add and store the key
		keyList.addKey(server, serverPublicKey);

		try
		{
			ObjectOutputStream outStream = new ObjectOutputStream(new FileOutputStream(userFolder+keyFile));
			outStream.writeObject(keyList);
			outStream.close();
			return true;
		}
		catch(IOException ex)
		{
			System.out.println(cEngine.formatAsSuccess("UserKeys file does not exist. Creating one now"));
			ex.printStackTrace(System.err);
			return false;
		}
	}
}
