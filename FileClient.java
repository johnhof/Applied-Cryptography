/* FileClient provides all the client functionality regarding the file server */

import java.util.List;
import java.security.*;
import javax.crypto.*;
import java.io.*;
import javax.crypto.spec.IvParameterSpec;
import java.util.Random;
import java.security.SecureRandom;
import java.util.*;

public class FileClient extends Client implements FileClientInterface 
{
	private Key serverPublicKey;
	private KeyList keyList;
	private UserToken token;
	
	public boolean connect(final String server, final int port, String username, UserToken newtoken)
	{
		System.out.println("\n*** Attempting to connect to File Server: NAME: " + server + "; PORT: " + port + " ***");
		super.connect(server, port);

		token = newtoken;
		
		String userFolder = "User_Resources/";
		String userFile = userFolder+"UserKeys" + username + ".bin";
		ObjectInputStream keyStream;
		
		System.out.println("\nSetting up resources");

		try
		{
			//Create or find a directory named "shared_files"
			File file = new File("User_Resources");
			file.mkdir();

			FileInputStream fis = new FileInputStream("User_Resources/"+userFile);
			keyStream = new ObjectInputStream(fis);
			keyList = (KeyList)keyStream.readObject();

			if(keyList.checkServer(server))
			{
				//we have connected before
				serverPublicKey = keyList.getKey(server);
				Key allegedKey = setPublicKey();
				if(serverPublicKey.toString().equals(allegedKey.toString()))
				{
					System.out.println(cEngine.formatAsSuccess("FileServer verification step 1 complete"));
				}
				else
				{
					System.out.println(cEngine.formatAsError("Public Keys Do Not Match. This is an unauthorized server"));
					System.exit(-1);
				}
			}
			else
			{
				System.out.println(cEngine.formatAsSuccess("This is a new file server. Requesting Public Key"));
				serverPublicKey = setPublicKey();
				keyList.addKey(server, serverPublicKey);
				ObjectOutputStream outStream = new ObjectOutputStream(new FileOutputStream(userFolder+"UserKeys" + username + ".bin"));
				outStream.writeObject(keyList);
				outStream.close();
			}
		}
		catch(FileNotFoundException e)
		{
			System.out.println(cEngine.formatAsSuccess("UserKeys file does not exist. Creating new one"));
			keyList = new KeyList();
			System.out.println(cEngine.formatAsSuccess("This is a new file server. Requesting Public Key"));
			serverPublicKey = setPublicKey();
			keyList.addKey(server, serverPublicKey);
			try
			{
				ObjectOutputStream outStream = new ObjectOutputStream(new FileOutputStream(userFolder+"UserKeys" + username + ".bin"));
				outStream.writeObject(keyList);
				outStream.close();
			}
			catch(Exception ex)
			{
				System.out.println("ERROR: FILECLIENT: COULD NOT WRITE USERKEYS");
				ex.printStackTrace();
				System.exit(-1);
			}
		}
		catch(Exception e)
		{
			System.out.println("ERROR: FILECLIENT: COULD NOT FINISH CONNECTION");
			e.printStackTrace();
			System.exit(-1);
		}
		
		setAesKey(token);
		
		System.out.println("\n*** File server connection successful: NAME: " + serverName + "; PORT: " + serverPort + " ***");

		return true;
	}

	public void setToken(UserToken newtoken)
	{
		token = newtoken;
	}
	
	//This function also authenticats the fileserver
	public void setAesKey(UserToken token)
	{
		try{
			Envelope message, response;
			aesKey = cEngine.genAESKeySet();
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
		
			message = new Envelope("AESKEY");
			message.addObject(token);
			message.addObject(encryptedKey);
			message.addObject(aesKey.getIV().getIV());
		
			System.out.println("\nFile Server Request Sent: AESKEY");
			writePlainText(message);
			//THE AES KEY IS NOW SET


			message = new Envelope("CHALLENGE");
			Integer challenge = new Integer((new SecureRandom()).nextInt());
			message.addObject(token);
			message.addObject(challenge);
			System.out.println("\nFile Server Request Sent: CHALLENGE");
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
					java.sql.Timestamp challengeTime = (java.sql.Timestamp)response.getObjContents().get(1);
					if((System.currentTimeMillis() - challengeTime.getTime())/(1000*60) < 5 )
					{
						System.out.println(cEngine.formatAsSuccess("Fresh timestamp returned"));
					}
					else
					{
						System.out.println(cEngine.formatAsError("Old timestamp"));
						System.exit(-1);
					}
				}
			}
		}
		catch(Exception e)
		{
			System.out.println("ERROR:FILECLIENT: COULD NOT SEND AESKEY");
			e.printStackTrace();
			System.exit(-1);
		}
	}
	
	
	public Key setPublicKey()
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
			System.exit(-1);
		}
		return answer;
	}
	
	public boolean delete(String filename, UserToken token) 
	{
		String remotePath;
		//remove the  leading '/' if necessary
		if (filename.charAt(0)=='/') 
		{
			remotePath = filename.substring(1);
		}
		else 
		{
			remotePath = filename;
		}

		//create and setup a 'delete' envelope
		Envelope env = new Envelope("DELETEF"); //Success
	    env.addObject(remotePath);
	    env.addObject(token);

	    //send the envelope and output the result

		System.out.println("\nFile Server Request Sent: DELETEF");
		writePlainText(env);
		//writeEncrypted(env);
		//SWTICH

	    env = (Envelope)readPlainText();
		    
		if (env.getMessage().compareTo("OK")==0) 
		{
			System.out.printf("File %s deleted successfully\n", filename);				
		}
		else 
		{
			System.out.printf("%sError deleting file %s (%s)\n", cEngine.formatAsError(""), filename, env.getMessage());
			return false;
		}
	    	
		return true;
	}

	public boolean download(String sourceFile, String destFile, UserToken token) 
	{
		//remove the  leading '/' if necessary
		if (sourceFile.charAt(0)=='/') 
		{
			sourceFile = sourceFile.substring(1);
		}
		
		//download the file
		File file = new File(destFile);
		try 
		{
		    if (!file.exists()) 
		    {
			   	file.createNewFile();
			    FileOutputStream fos = new FileOutputStream(file);
			    
			    //create and setup a download envelope
			    Envelope env = new Envelope("DOWNLOADF"); //Success
			    env.addObject(sourceFile);
			    env.addObject(token);
				System.out.println("\nFile Server Request Sent: DOWNLOADF");
			    writePlainText(env); 
				//writeEncrypted(env);
				//SWTICH

						
				//retreive the incoming evelope
			    env = (Envelope)readPlainText();
						    
				//read the body of the file one envelope at a time
				while (env.getMessage().compareTo("CHUNK")==0) 
				{ 
					fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));
					System.out.printf(".");
					env = new Envelope("DOWNLOADF"); //Success
					writePlainText(env);
					//writeEncrypted(env);
					//SWTICH
					env = (Envelope)readPlainText();									
				}										
				fos.close();
						
				//when the end of file is detected, close and display the appropriate message
				if(env.getMessage().compareTo("EOF")==0) 
				{
				    fos.close();
					System.out.printf("\nTransfer successful file %s\n", sourceFile);
					env = new Envelope("OK"); //Success
					writePlainText(env);
					//writeEncrypted(env);
					//SWTICH
				}
				else 
				{
					System.out.printf("%sError reading file %s (%s)\n", cEngine.formatAsError(""), sourceFile, env.getMessage());
					file.delete();
					return false;								
				}
			}    		 
			else 
			{
			    System.out.printf("%scouldn't create file %s\n", cEngine.formatAsError(""), destFile);
				return false;
			}	
		} 
		catch (IOException e1) 
		{
		   	System.out.printf("%scouldn't create file %s\n", cEngine.formatAsError(""), destFile);
		  	return false;
		}
		return true;
	}

	@SuppressWarnings("unchecked")
	public List<ShareFile> listFiles(UserToken token) 
	{
		 try
		 {
			Envelope message = null, e = null;
			//Tell the server to return the member list
			message = new Envelope("LFILES");
			message.addObject(token); //Add requester's token
			System.out.println("\nFile Server Request Sent: LFILES");
			writePlainText(message); 
			//writeEncrypted(message);
			//SWTICH
			 
			e = (Envelope)readPlainText();
			 
			//If server indicates success, return the member list
			if(e.getMessage().equals("OK"))
			{ 
				System.out.println(cEngine.formatAsSuccess("Files returned"));
				return (List<ShareFile>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			}
			System.out.println(cEngine.formatAsError("No files returned"));
			return null;
			 
		 }
		 catch(Exception e)
		{
			System.err.println(cEngine.formatAsError("Exception encountered"));
			e.printStackTrace(System.err);
			return null;
		}
	}

	public boolean upload(String sourceFile, String destFile, String group,
			UserToken token) 
	{
		//add a leading '/' if necessary
		if (destFile.charAt(0)!='/') 
		{
			 destFile = "/" + destFile;
		}
		
		try
		{
			Envelope message = null, env = null;
			//Tell the server to return the member list
			message = new Envelope("UPLOADF");
			message.addObject(destFile);
			message.addObject(group);
			message.addObject(token); //Add requester's token
			System.out.println("\nFile Server Request Sent: UPLOADF");
			writePlainText(message);
			//writeEncrypted(message);
			//SWTICH
			
			 
			FileInputStream fis = new FileInputStream(sourceFile);
			 
			env = (Envelope)readPlainText();
			 
			//If server indicates success, return the member list
			if(env.getMessage().equals("READY"))
			{ 
				System.out.printf("Meta data upload successful\n");
				
			}
			 else 
			{
				
				System.out.printf("Upload failed: %s\n", env.getMessage());
				return false;
			}
			 
		 	//unless an error occurs, write the file in 4096 byte chunks
			do 
			{
				byte[] buf = new byte[4096];
				if (env.getMessage().compareTo("READY")!=0) 
				{
					System.out.printf("%sServer error: %s\n", cEngine.formatAsError(""), env.getMessage());
					return false;
				}
				message = new Envelope("CHUNK");
				int n = fis.read(buf); //can throw an IOException
				if (n > 0) 
				{
					System.out.printf(".");
				} 
				else if (n < 0) 
				{
					System.out.println(cEngine.formatAsError("Read error"));
					return false;
				}
					
				message.addObject(buf);
				message.addObject(new Integer(n));
					
				writePlainText(message);
				//writeEncrypted(message);
				//SWTICH
						
				env = (Envelope)readPlainText();
					
										
			 }
			 while (fis.available()>0);		 
					 
			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 { 
				
				//tell the sever we're done
				message = new Envelope("EOF");
				writePlainText(message);
				//writeEncrypted(message);
				//SWTICH
	        	System.out.println(cEngine.formatAsSuccess("EOF sent"));
				
				env = (Envelope)readPlainText();
				if(env.getMessage().compareTo("OK")==0) 
				{
					System.out.printf("%sFile data upload successful: %s\n", cEngine.formatAsSuccess(""), sourceFile+" -> "+destFile);
				}
				else 
				{
					System.out.printf("%sUpload failed: %s\n", cEngine.formatAsError(""), env.getMessage());
					return false;
				}
				
			}
			else {
				
				System.out.printf("%sUpload failed: %s\n", cEngine.formatAsError(""), env.getMessage());
				return false;
			}	 
		}
		catch(Exception e1)
		{
			//NOTE: this may be some other problem, I dont know what other exceptions are being thrown here
			System.out.println(cEngine.formatAsError("Exception encountered, make sure the file exists"));
			return false;
		}
		return true;
	}

}

