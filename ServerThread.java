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
	
//----------------------------------------------------------------------------------------------------------------------
//-- CONNECTION SETUP FUNCIONS
//----------------------------------------------------------------------------------------------------------------------
	protected boolean setUpConection()
	{
		Envelope message = null;
		Envelope response = null;

		try
		{
			message = (Envelope)cEngine.readPlainText(input);

//-- PUBLIC KEY DISTIBURTION------------------------------------------------------------------------------------------

			//if they sent a public key request
			if(message.getMessage().equals("GET_PUBKEY"))
			{
				System.out.println("\n<< Request Recieved: " + message.getMessage());

				//send your key
				response = new Envelope("OK");
				System.out.println(">> Sending Reponse: OK");
				response.addObject(myPublicKey);
				cEngine.writePlainText(response, output);
				System.out.println(cEngine.formatAsSuccess("public key sent"));

				//expect a new message
				message = (Envelope)cEngine.readPlainText(input);
				System.out.println("\n<< Request Recieved: " + message.getMessage());
			}
		
//--RECIEVE AES KEY---------------------------------------------------------------------------------------------------

			if(message.getMessage().equals("SET_AESKEY"))
			{
				System.out.println(cEngine.formatAsSuccess("Attempting to decrypt with private key"));
				//decrypt the key and challenge
				aesKey = byteToAESKey((byte[])message.getObjContents().get(0),new IvParameterSpec((byte[])message.getObjContents().get(1)));
				Integer challenge = (Integer)cEngine.deserialize(cEngine.RSADecrypt((byte[])message.getObjContents().get(2), myPrivateKey));
				System.out.println(cEngine.formatAsSuccess("Challenge decrypted with private key"));
				
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
				cEngine.writePlainText(genAndPrintErrorEnvelope("Unexpected request"), output);
				return false;
			}
		}
		catch(Exception exc)
		{
			cEngine.writePlainText(genAndPrintErrorEnvelope("Exception thrown during setup"), output);
			return false;
		}

		return true;
	}

//--CONVERT BYTE ARRAY TO KEY---------------------------------------------------------------------------------------------------
	protected AESKeySet byteToAESKey(byte [] aesKeyBytes, IvParameterSpec IV)
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

			return new AESKeySet((Key)localInput.readObject(), IV);
		}
		catch(Exception exc)
		{
			System.out.println("\nERROR: FILECLIENT; AES Key to enctrypted byte stream conversion failed");
			return null;
		}

	}

//----------------------------------------------------------------------------------------------------------------------
//-- UTILITY FUNCITONS
//----------------------------------------------------------------------------------------------------------------------

	protected Envelope genAndPrintErrorEnvelope(String error)
	{
		if(cEngine == null)	cEngine = new CryptoEngine();

		System.out.println(cEngine.formatAsError(error));
		return new Envelope(error);
	}

	protected void rejectToken(Envelope response, ObjectOutputStream output)
	{
		cEngine.writeAESEncrypted(genAndPrintErrorEnvelope("Token signature rejected"), aesKey, output);
		try
		{
			socket.close();
		}
		catch(Exception e)
		{
			System.out.println("WARNING: GroupThread; socket could not be closed");
		}
	}
	
}