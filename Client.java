import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
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
	protected GroupKeyMapController groupFileKeyMap;
	protected Integer msgNumber = 0;
	protected SecretKeySpec HMACKey;
	


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
			//grab/create the shared instance of our keymap
			groupFileKeyMap = GroupKeyMapController.getInstance(userName, userFolder);

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
			//message.addObject(AESKeyToByte());
			message.addObject(cEngine.RSAEncrypt(cEngine.serialize(aesKey.getKey()), serverPublicKey));
			message.addObject(aesKey.getIV().getIV());
			message.addObject(cEngine.RSAEncrypt(cEngine.serialize(challenge), serverPublicKey));

			//Matt, take note -HMAC-
			HMACKey = cEngine.genHMACKey();
			message.addObject(HMACKey);//key
			message = cEngine.attachHMAC(message, HMACKey);

			System.out.println(cEngine.formatAsSuccess("RSA encryption successful, IV sent in plaintext"));
		
			cEngine.writePlainText(message, output);
			//THE AES KEY IS NOW SET

			System.out.println("<< Receiving Response: OK");
			response = (Envelope)cEngine.readAESEncrypted(aesKey, input);
			if(response.getMessage().equals("OK"))
			{
				//cehck message size
				if(response.getObjContents().size()<3)
				{
					System.out.println(cEngine.formatAsError("Message too small"));
				}
				else if((challenge.intValue()+1) != ((Integer)response.getObjContents().get(1)).intValue())
				{
					System.out.println(cEngine.formatAsError("Challenge failed, server rejected"));
				}
				else if(cEngine.checkHMAC(response, HMACKey))
				{
					System.out.println(cEngine.formatAsSuccess("Challenge passed, server authenticated"));
					msgNumber = (Integer)response.getObjContents().get(0);
					System.out.println(cEngine.formatAsSuccess("Initial message number set to: "+msgNumber.intValue()));
					return true;
				}

			}
			else
			{
				System.out.println(cEngine.formatAsError("Unexpected response: "+response.getMessage()));
			}
		}
		catch(Exception e)
		{
			System.out.println(cEngine.formatAsError("Server failed to authenticate"));
			return false;
		}
		return false;
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
				System.out.println("<< Receiving Response: OK");
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


	protected boolean checkMessagePreReqs(Envelope message)
	{
				//make sure the message has a minimum number of contents
		if(message.getObjContents().size() < 2)
		{
        	System.out.println(cEngine.formatAsError("Message too short"));
			return false;//go back and wait for a new message
		}
		Integer reqMsgNumber = (Integer)message.getObjContents().get(0);

		//Matt, take note -HMAC -
		if(!cEngine.checkHMAC(message, HMACKey)) return false;

        //check message number
		if(msgNumber != reqMsgNumber)
		{
        	System.out.println(cEngine.formatAsError("Message number does not match: "+reqMsgNumber));
			return false;
		}
        System.out.println(cEngine.formatAsSuccess("Message number matches"));
		msgNumber++;
				
		return true;
	}
}
