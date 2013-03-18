/* superclass used to share functions between  file and group servers*/

import java.lang.Thread;
import java.net.Socket;
import java.util.*;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

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

			message = (Envelope)cEngine.readPlainText(input);
			if(message.getMessage().equals("GET_PUBKEY"))
			{
				System.out.println("\n<< Request Recieved: " + message.getMessage());
				response = new Envelope("OK");
				System.out.println(">> Sending Reponse: OK");
				response.addObject(myPublicKey);
				cEngine.writePlainText(response, output);
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
			message = (Envelope)cEngine.readPlainText(input);
			if(message.getMessage().equals("SET_AESKEY"))
			{
				System.out.println("\n<< Request Received: " + message.getMessage());

				//decrypt the key and challenge
				aesKey = new AESKeySet((Key) cEngine.deserialize(cEngine.RSADecrypt((byte[])message.getObjContents().get(0), myPrivateKey)), 
										(IvParameterSpec)message.getObjContents().get(1));
				Integer challenge = (Integer)cEngine.deserialize(cEngine.RSADecrypt((byte[])message.getObjContents().get(2), myPrivateKey));
				
				System.out.println(cEngine.formatAsSuccess("RSA decryption successful,"));
				System.out.println(cEngine.formatAsSuccess("AES keyset recieved and stored"));
				//THE AES KEY IS NOW SET

	//--CHALLENGE---------------------------------------------------------------------------------------------------------
				challenge = new Integer((challenge.intValue()+1));

				response = new Envelope("OK");
				System.out.println(">> Sending Reponse: OK");
				response.addObject(challenge);
				cEngine.writeAESEncrypted(response, aesKey, output);
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
	
}