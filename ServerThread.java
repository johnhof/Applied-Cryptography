/* superclass used to share functions between  file and group servers*/

import java.lang.Thread;
import java.net.Socket;
import java.util.List;
import java.util.ArrayList;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.util.*;

//These threads are spun off by FileServer.java
public class ServerThread extends Thread
{
	protected final Socket socket;
	protected CryptoEngine cEngine;
	protected AESKeySet aesKey;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;
	protected Server myServer;
	protected Key myPrivateKey;
	protected Key myPublicKey;

	public ServerThread(Server server, Socket _socket)
	{
		socket = _socket;
		cEngine = new CryptoEngine();
		aesKey = null;
		myServer = server;
		myPrivateKey = myServer.getAuthKeys().getPrivate();
		myPublicKey = myServer.getAuthKeys().getPublic();
		try
		{
			input = new ObjectInputStream(socket.getInputStream());
			output = new ObjectOutputStream(socket.getOutputStream());
		}
		catch(Exception exc)
		{
			System.out.println(cEngine.formatAsError("failed to bind streams to the socket"));
		}
	}

	protected Envelope genAndPrintErrorEnvelope(String error)
	{
		if(cEngine == null)	cEngine = new CryptoEngine();

		System.out.println(cEngine.formatAsError(error));
		return new Envelope(error);
	}
	
//----------------------------------------------------------------------------------------------------------------------
//-- CONNECTION SETUP FUNCIONS
//----------------------------------------------------------------------------------------------------------------------
	protected boolean setUpConection()
	{
		Envelope message = null;
		Envelope response = null;

//--HANLE PUBLIC KEY DISTIBURTION-------------------------------------------------------------------------------------

		try
		{
			//These keys exist just to encrypt/decrypt this specific session key for this user

			 message = (Envelope)input.readObject();
			if(message.getMessage().equals("PUBKEYREQ"))
			{
				System.out.println("\nRequest received: " + message.getMessage());
				response = new Envelope("OK");
				response.addObject(myPublicKey);
				output.writeObject(response);
				System.out.println(cEngine.formatAsSuccess("public key sent"));
			}
			else
			{
				System.out.println(cEngine.formatAsError("Unexpected message type"));
				socket.close();
				return false;
			}	
		}
		catch(Exception e)
		{
			e.printStackTrace();
			return false;
		}
			
		
//--RECIEVE AES KEY---------------------------------------------------------------------------------------------------
		try
		{
			message = (Envelope)input.readObject();
			if(message.getMessage().equals("AESKEY"))
			{
				System.out.println("\nRequest received: " + message.getMessage());

				//convert the session key back from a byte array
				aesKey = byteToAESKey((byte[]) message.getObjContents().get(0), new IvParameterSpec((byte[])message.getObjContents().get(1)));

				System.out.println(cEngine.formatAsSuccess("AES keyset recieved and stored"));
				//THE AES KEY IS NOW SET

	//--CHALLENGE---------------------------------------------------------------------------------------------------------
				Integer challenge = (Integer)message.getObjContents().get(2);
				challenge = new Integer((challenge.intValue()+1));

				response = new Envelope("OK");
				response.addObject(challenge);
				writeObject(response);
				System.out.println(cEngine.formatAsSuccess("Challenge answered"));
			}
			else 
			{
				return false;
			}
		}
		catch(Exception exc)
		{
			System.out.println(cEngine.formatAsError("IO excepetion while setting AES key"));
			return false;
		}

		return true;
	}

	//--CONVERT KEY TO BYTE ARRAY------------------------------------------------------------------------------------------
	protected AESKeySet byteToAESKey(byte[] aesKeyBytes, IvParameterSpec IV)
	{
		try
		{
			byte[] aesKeyBytesA = new byte[128];
			byte[] aesKeyBytesB = new byte[128];
				
			System.arraycopy(aesKeyBytes, 0, aesKeyBytesA, 0, 128);
			System.arraycopy(aesKeyBytes, 128, aesKeyBytesB, 0, 128);
				
			aesKeyBytesA = cEngine.RSADecrypt(aesKeyBytesA, myPrivateKey);
			aesKeyBytesB = cEngine.RSADecrypt(aesKeyBytesB, myPrivateKey);
			
			System.out.println(cEngine.formatAsSuccess("AES key decrypted with private key"));
					
			System.arraycopy(aesKeyBytesA, 0, aesKeyBytes, 0, 100);
			System.arraycopy(aesKeyBytesB, 0, aesKeyBytes, 100, 41);
				
			ByteArrayInputStream fromBytes = new ByteArrayInputStream(aesKeyBytes);
			ObjectInputStream localInput = new ObjectInputStream(fromBytes);

			return new AESKeySet((Key) localInput.readObject(), IV);
		}
		catch(Exception exc)
		{
			System.out.println("ERROR:FILECLIENT; AESKEY TO BYTE STREAM CONVERSION FAILED");
			return null;
		}
	}

//----------------------------------------------------------------------------------------------------------------------
//-- COMMUNICATION FUNCITONS
//----------------------------------------------------------------------------------------------------------------------

	//Method to write objects
	protected boolean writeObject(Object obj)
	{
		try
		{			
			byte[] eData = cEngine.AESEncrypt(cEngine.serialize(obj), aesKey);//encrypt the data

			System.out.println(cEngine.formatAsSuccess("AES encryption successful"));

			output.writeObject(eData);//write the data to the client
		}
		catch(Exception e)
		{
			System.out.println(cEngine.formatAsError("IO/ClassNotFound Exception when writing (Encrypted) data"));
			return false;
		}
		return true;
	}


	protected Object readObject()
	{
		Object obj = null;
		try
		{
			byte[] data = cEngine.AESDecrypt((byte[])input.readObject(), aesKey);

			System.out.println(cEngine.formatAsSuccess("AES decryption successful"));

			obj = cEngine.deserialize(data);
		}
		catch(Exception ex)
		{
			System.out.println(cEngine.formatAsError("IO/ClassNotFound Exception when reading (Encrypted) data"));
			ex.printStackTrace();
		}
		
		return obj;
	}
	
}