/* superclass used to share functions between  file and group servers*/

import java.lang.Thread;
import java.net.Socket;
import java.util.*;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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
	protected Integer msgNumber = 0;
	protected SecretKeySpec HMACKey;

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
	protected boolean setUpConnection()
	{
		Envelope message = null;
		Envelope response = null;

		try
		{
			message = (Envelope)cEngine.readPlainText(input);
			System.out.println("\n<< Request Received: " + message.getMessage());

//-- PUBLIC KEY DISTIBUTION-------------------------------------------------------------------------------------------

			//if they sent a public key request
			if(message.getMessage().equals("GET_PUBKEY"))
			{
				//send your key
				response = new Envelope("OK");
				System.out.println(">> Sending Reponse: OK");
				response.addObject(myPublicKey);
				cEngine.writePlainText(response, output);
				System.out.println(cEngine.formatAsSuccess("public key sent"));

				//expect a new message
				message = (Envelope)cEngine.readPlainText(input);
				System.out.println("\n<< Request Received: " + message.getMessage());
			}
		
//--RECIEVE AES KEY---------------------------------------------------------------------------------------------------

			if(message.getMessage().equals("SET_AESKEY"))
			{
				//generate and store a message number
				msgNumber = new Integer((new SecureRandom()).nextInt());

				if(message.getObjContents().size()<5)
				{
					cEngine.writePlainText(genAndPrintErrorEnvelope("Message too short"), output);
					return false;
				}

				//decrypt the key and challenge
				aesKey = byteToAESKey((byte[])message.getObjContents().get(0),new IvParameterSpec((byte[])message.getObjContents().get(1)));
				Integer challenge = (Integer)cEngine.deserialize(cEngine.RSADecrypt((byte[])message.getObjContents().get(2), myPrivateKey));
				
				//store the HMAC key, and cehck the message -HMAC-
				HMACKey = (SecretKeySpec)message.getObjContents().get(3); //TODO: make this RSA encrypted -HMAC-
				if(!cEngine.checkHMAC(message, HMACKey)) return false;

				if(aesKey == null || challenge == null)
				{
					cEngine.writePlainText(genAndPrintErrorEnvelope("Could not decrypt message contents"), output);
					return false;
				}
				else System.out.println(cEngine.formatAsSuccess("Challenge decrypted with private key"));
				
				System.out.println(cEngine.formatAsSuccess("AES keyset received and stored"));
				//THE AES KEY IS NOW SET

	//--CHALLENGE---------------------------------------------------------------------------------------------------------
				challenge = new Integer((challenge.intValue()+1));

				response = new Envelope("OK");
				System.out.println(">> ("+msgNumber+"): Sending Reponse: OK");
				response.addObject(msgNumber);
				response.addObject(challenge);
				//Matt, take note -HMAC-
				response = cEngine.attachHMAC(response, HMACKey); 
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
			return new AESKeySet((Key)cEngine.deserialize(cEngine.RSADecrypt(aesKeyBytes, myPrivateKey)), IV);
		}
		catch(Exception exc)
		{
			System.out.println("\nERROR: FILECLIENT; AES Key from encrypted byte stream conversion failed");
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
		Envelope response = new Envelope(error);
		response.addObject(msgNumber);
        //Matt, take note -HMAC-
        if(HMACKey !=null)response = cEngine.attachHMAC(response, HMACKey);
		return response;
	}

	protected UserToken checkMessagePreReqs(Envelope message, Envelope response, PublicKey sigKey)
	{

		//make sure the message has a minimum number of contents
		if(message.getObjContents().size() < 3)
		{
			cEngine.writeAESEncrypted(genAndPrintErrorEnvelope("The message was too short"), aesKey, output);
			return null;//go back and wait for a new message
		}

		UserToken reqToken = (UserToken)message.getObjContents().get(0);
		Integer reqMsgNumber = (Integer)message.getObjContents().get(1);

		//Matt, take note -HMAC -
		if(!cEngine.checkHMAC(message, HMACKey)) return null;

		//check token validity
		if(reqToken != null && !reqToken.verifySignature(sigKey, cEngine))
		{
			rejectToken(response, output);
			return null;
		}
        System.out.println(cEngine.formatAsSuccess("Token Authenticated"));

        //check message number
		if(msgNumber.intValue() != reqMsgNumber.intValue())
		{
			rejectMessageNumber(response, reqMsgNumber, output);
			return null;
		}
        System.out.println(cEngine.formatAsSuccess("Message number matches"));
		msgNumber++;
				
		return reqToken;
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

	protected void rejectMessageNumber(Envelope response, Integer reqMsgNumber, ObjectOutputStream output)
	{
		cEngine.writeAESEncrypted(genAndPrintErrorEnvelope("Message number does not match: "+reqMsgNumber+" : "+msgNumber), aesKey, output);
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