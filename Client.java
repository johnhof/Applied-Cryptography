import java.net.*;
import java.security.*;
import javax.crypto.*;
import java.io.*;
import java.util.*;

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
	private Key serverPublicKey;

	//NOTE: I removed the feedback from this since it's called by its subclasses, object specific feedback is printed there - john, 3/16
		//I just noticed that this probably the most famous bible verse. your move athiests 
	public boolean connect(final String server, final int port, String username) 
	{
		serverName = server;
		serverPort = port;
		userName = username;
		userFolder = "User_Resources/";

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



//----------------------------------------------------------------------------------------------------------------------
//-- COMMUNICATION FUNCITONS
//----------------------------------------------------------------------------------------------------------------------

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


//----------------------------------------------------------------------------------------------------------------------
//-- CONNECTION SETUP FUNCIONS
//----------------------------------------------------------------------------------------------------------------------

	protected boolean setUpServer(String server, String userFile)
	{

//--ATHENTICATE SERVER--------------------------------------------------------------------------------------------------
		
		ObjectInputStream keyStream;
		
		System.out.println("\nSetting up resources");
		try
		{
			//Create or find a directory named "shared_files"
			File file = new File("User_Resources");
			file.mkdir();

			//Read in the key
			FileInputStream fis = new FileInputStream(userFolder+userFile);
			keyStream = new ObjectInputStream(fis);
			keyList = (KeyList)keyStream.readObject();

			//If we have connected
			if(keyList.checkServer(server))
			{
				//retrieve the key from the server
				serverPublicKey = keyList.getKey(server);
				Key allegedKey = getPublicKey();
				if(serverPublicKey == null) return false;

				//sompare the keys
				if(serverPublicKey.toString().equals(allegedKey.toString()))
				{
					System.out.println(cEngine.formatAsSuccess("Server verification step 1 complete"));
				}
				else
				{
					System.out.println(cEngine.formatAsError("Public Keys Do Not Match. This is an unauthorized server"));
					return false;
				}
			}
			//If its a new server
			else
			{
				//Retrieve the key
				System.out.println(cEngine.formatAsSuccess("This is a new server. Requesting Public Key"));
				serverPublicKey = getPublicKey();
				if(serverPublicKey == null) return false;

				//Add and store the key
				keyList.addKey(server, serverPublicKey);
				ObjectOutputStream outStream = new ObjectOutputStream(new FileOutputStream(userFolder+"UserKeys" + userName + ".bin"));
				outStream.writeObject(keyList);
				outStream.close();
			}
		}
		catch(FileNotFoundException exc)
		{
			System.out.println(cEngine.formatAsSuccess("UserKeys file does not exist. Creating new one"));
			
			//Retrieve the key
			System.out.println(cEngine.formatAsSuccess("This is a new file server. Requesting Public Key"));
			serverPublicKey = getPublicKey();
			if(serverPublicKey == null) return false;
			
			//Add and store the key
			keyList = new KeyList();
			keyList.addKey(server, serverPublicKey);
			try
			{
				ObjectOutputStream outStream = new ObjectOutputStream(new FileOutputStream(userFolder+"UserKeys" + userName + ".bin"));
				outStream.writeObject(keyList);
				outStream.close();
			}
			catch(Exception ex)
			{
				System.out.println("ERROR: FILECLIENT: COULD NOT WRITE USERKEYS");
				ex.printStackTrace();
				return false;
			}
		}
		catch(Exception exc)
		{
			System.out.println("ERROR: FILECLIENT: COULD NOT FINISH CONNECTION");
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
			message = new Envelope("AESKEY");
			message.addObject(AESKeyToByte());
			message.addObject(aesKey.getIV().getIV());
			message.addObject(challenge);
		
			System.out.println("\nFile Server Request Sent: AESKEY");
			writePlainText(message);
			//THE AES KEY IS NOW SET

			response = (Envelope)readPlainText();
			if(response.getMessage().equals("OK"))
			{
				if((challenge.intValue()+1) != ((Integer)response.getObjContents().get(0)).intValue())
				{
					System.out.println(cEngine.formatAsError("Challenge failed"));
					return false;
				}
				else
				{
					System.out.println(cEngine.formatAsSuccess("Challenge passed"));
				}
			}
		}
		catch(Exception e)
		{
			System.out.println("ERROR:FILECLIENT: COULD NOT SEND AESKEY");
			e.printStackTrace();
			return false;
		}
		return true;
	}

//--GET PUBLIC KEY---------------------------------------------------------------------------------------------------
	protected Key getPublicKey()
	{	
		Envelope message, response;
		Key answer = null;
		try
		{
			message = new Envelope("PUBKEYREQ");
			System.out.println("\nFile Server Request Sent: PUBKEYREQ");
			writePlainText(message);
			response = (Envelope)readPlainText();
			if(response.getMessage().equals("OK"))
			{
				answer = (Key)response.getObjContents().get(0);
				System.out.println(cEngine.formatAsSuccess("public key obtained"));
				return answer;
			}
		}
		catch(Exception e)
		{
			System.out.println("ERROR: FILECLIENT: FAILED TO RECEIVE PUBLIC KEY");
			e.printStackTrace();
			return null;
		}
		return answer;
	}

//--CONVERT KEY TO BYTE ARRAY------------------------------------------------------------------------------------------
	protected byte[] AESKeyToByte()
	{
		try
		{
			ByteArrayOutputStream toBytes = new ByteArrayOutputStream();//create ByteArrayOutputStream
			ObjectOutputStream localOutput = new ObjectOutputStream(toBytes);//Make an object outputstream to that bytestream
				
			localOutput.writeObject(aesKey.getKey());//write to the bytearrayoutputstream
			
			byte[] aesKeyBytes = toBytes.toByteArray();
			
			byte[] aesKeyBytesA = new byte[100];
			byte[] aesKeyBytesB = new byte[41];
			
			System.arraycopy(aesKeyBytes, 0, aesKeyBytesA, 0, aesKeyBytesA.length);
			System.arraycopy(aesKeyBytes, 100, aesKeyBytesB, 0, aesKeyBytes.length-100);
		
			byte[] encryptedKeyA = cEngine.RSAEncrypt(aesKeyBytesA, serverPublicKey);
			byte[] encryptedKeyB = cEngine.RSAEncrypt(aesKeyBytesB, serverPublicKey);
		
			byte[] encryptedKey = new byte[encryptedKeyA.length + encryptedKeyB.length];
			System.arraycopy(encryptedKeyA, 0, encryptedKey, 0, encryptedKeyA.length);
			System.arraycopy(encryptedKeyB, 0, encryptedKey, encryptedKeyA.length, encryptedKeyB.length);

			return encryptedKey;
		}
		catch(Exception exc)
		{
			System.out.println("ERROR:FILECLIENT: AESKEY TO BYTE STREAM CONVERSION FAILED");
			return null;
		}
	}
}
