/* FileClient provides all the client functionality regarding the file server */

import java.util.List;
import java.security.*;
import javax.crypto.*;
import java.io.*;
import java.util.*;

public class FileClient extends Client implements FileClientInterface 
{
	private UserToken token;
	
	public boolean connect(final String server, final int port, String username, UserToken newtoken)
	{
		System.out.println("\n*** Attempting to connect to File Server: NAME: " + server + "; PORT: " + port + " ***");
		
		super.connect(server, port, username);

		token = newtoken;
		
		if(setUpServer(server)==false)
		{
			System.out.println("\n!!! File server connection failed: NAME: " + serverName + "; PORT: " + serverPort + " !!!");
			return false;
		}
		
		System.out.println("\n*** File server connection successful: NAME: " + serverName + "; PORT: " + serverPort + " ***");

		return true;
	}

	public void setToken(UserToken newtoken)
	{
		token = newtoken;
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
	    env.addObject(token);
	    env.addObject(remotePath);

	    //send the envelope and output the result

		System.out.println("\n>> Sending File Server Request: DELETEF");
		cEngine.writeAESEncrypted(env, aesKey, output);

	    env = (Envelope)cEngine.readAESEncrypted(aesKey, input);
		    
		if (env.getMessage().compareTo("OK")==0) 
		{
			System.out.println("<< receiving File Server Response: OK");
			System.out.println(cEngine.formatAsSuccess("Successfully deleted file: "+filename));				
		}
		else 
		{
			System.out.println(cEngine.formatAsError(env.getMessage()));
			return false;
		}
	    	
		return true;
	}

	public boolean download(String sourceFile, String destFile, String group, UserToken token) 
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
			    
			    //create and setup a download envelope
			    Envelope env = new Envelope("DOWNLOADF"); //Success
			    env.addObject(token);
			    env.addObject(sourceFile);
				System.out.println("\n>> Sending File Server Request: DOWNLOADF");
			    cEngine.writeAESEncrypted(env, aesKey, output);

						
				//retreive the incoming evelope
			    env = (Envelope)cEngine.readAESEncrypted(aesKey, input);
			    byte[] encryptedFile = new byte[0];
						    
				//read the body of the file one envelope at a time
				while (env.getMessage().compareTo("CHUNK")==0) 
				{ 
					//fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));

					//append the new chunk onto the old
					byte[] temp = append(encryptedFile, (byte[])env.getObjContents().get(0));
					encryptedFile = temp;

					env = new Envelope("DOWNLOADF"); //Success
					cEngine.writeAESEncrypted(env, aesKey, output);

					env = (Envelope)cEngine.readAESEncrypted(aesKey, input);									
				}				
				recoverFileFromDownload(encryptedFile, file, group);
						
				//when the end of file is detected, close and display the appropriate message
				if(env.getMessage().compareTo("EOF")==0) 
				{
					System.out.println("<< receiving File Server Response: EOF");
					System.out.println(cEngine.formatAsSuccess("Transfer successful for file: "+sourceFile));
					env = new Envelope("OK"); //Success
					cEngine.writeAESEncrypted(env, aesKey, output);
				}
				else 
				{
					System.out.println(cEngine.formatAsError(env.getMessage()));
					file.delete();
					return false;								
				}
			}    		 
			else 
			{
			    System.out.println(cEngine.formatAsError("couldn't create file: "+destFile));
				return false;
			}	
		} 
		catch (IOException e1) 
		{
			System.out.println(cEngine.formatAsError("couldn't create file: "+destFile));
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
			System.out.println("\n>> Sending File Server Request: LFILES");
			cEngine.writeAESEncrypted(message, aesKey, output);
			 
			e = (Envelope)cEngine.readAESEncrypted(aesKey, input);
			 
			//If server indicates success, return the member list
			if(e.getMessage().equals("OK"))
			{ 
				System.out.println("<< receiving File Server Response: OK");
				System.out.println(cEngine.formatAsSuccess("Files returned"));
				return (List<ShareFile>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			}
			System.out.println(cEngine.formatAsError(e.getMessage()));
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
			message.addObject(token); //Add requester's token
			message.addObject(destFile);
			message.addObject(group);
			System.out.println("\n>> Sending File Server Request: UPLOADF");
			cEngine.writeAESEncrypted(message, aesKey, output);

			System.out.println(groupFileKeyMap.toString());

			env = (Envelope)cEngine.readAESEncrypted(aesKey, input);
			 
			//If server indicates success, return the member list
			if(env.getMessage().equals("READY"))
			{ 
				System.out.println("Meta data upload successful");
			}
			 else 
			{				
				System.out.println(cEngine.formatAsError(env.getMessage()));
				return false;
			}

			byte[] preparedFile = prepareFileForUpload(sourceFile, group);

			int byteCount=0;

		 	//unless an error occurs, write the file in 4096 byte chunks
			for(byteCount = 0; byteCount+4096<=preparedFile.length; byteCount+=4096)
			{
				byte [] buf = Arrays.copyOfRange(preparedFile, byteCount, byteCount+4096);

				if (env.getMessage().compareTo("READY")!=0) 
				{
					System.out.println("READY EXPECTED");
					System.out.println(env.getMessage());
					return false;
				}
				message = new Envelope("CHUNK");
					
				message.addObject(buf);
				message.addObject(new Integer(4096));
					
				cEngine.writeAESEncrypted(message, aesKey, output);
						
				env = (Envelope)cEngine.readAESEncrypted(aesKey, input);
	        	System.out.println(cEngine.formatAsSuccess("chunk sent..."));
			}

			//grab the last chunk if necessary (not evenly divisible by 4096)
			if(preparedFile.length-byteCount!=0) 
			{
				byte [] buf = Arrays.copyOfRange(preparedFile, byteCount, preparedFile.length);

				if (env.getMessage().compareTo("READY")!=0) 
				{
					System.out.println("READY EXPECTED");
					System.out.println(env.getMessage());
					return false;
				}
				message = new Envelope("CHUNK");
					
				message.addObject(buf);
				message.addObject(new Integer(preparedFile.length-byteCount));
					
				cEngine.writeAESEncrypted(message, aesKey, output);
						
				env = (Envelope)cEngine.readAESEncrypted(aesKey, input);
	        	System.out.println(cEngine.formatAsSuccess("chunk sent..."));
			}

			 if(env.getMessage().compareTo("READY")==0)
			 { 
				//tell the sever we're done
				message = new Envelope("EOF");
				cEngine.writeAESEncrypted(message, aesKey, output);
	        	System.out.println(cEngine.formatAsSuccess("EOF sent"));
				
				env = (Envelope)cEngine.readAESEncrypted(aesKey, input);
				if(env.getMessage().compareTo("OK")==0) 
				{
					System.out.println("<< receiving File Server Response: OK");
					System.out.println(cEngine.formatAsSuccess("File upload successful: "+sourceFile+" -> "+destFile.substring(1)));
				}
				else 
				{
					System.out.println(cEngine.formatAsError("Upload failed: "+env.getMessage()));
					return false;
				}
				
			}
			else {
				
				System.out.println(cEngine.formatAsError("Upload failed: "+env.getMessage()));
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

	public int verifyMsgNumber(PrivateKey myPrivate)
	{
		Integer msgNumber = null;
		//try
		//{
			Envelope response = (Envelope)cEngine.readAESEncrypted(aesKey, input);
			msgNumber = (Integer)response.getObjContents().get(0);
			
			token.setMsgNumber(msgNumber);
			token.signMsgNumber(myPrivate, cEngine);
		
			Envelope message = new Envelope("VERIFY_MN");
			message.addObject(token);
			cEngine.writeAESEncrypted(message, aesKey, output);
		//}
		/*catch(Exception e)
		{
			e.printStackTrace();
			System.exit(-1);
		}*/
		return msgNumber.intValue();
	}


//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-- TRANSFER UTILITY FUNCTIONS
//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

	private byte[] prepareFileForUpload(String sourceFile, String group)
	{
		AESKeySet key = groupFileKeyMap.getLatestKey(group, true);
		Date date = groupFileKeyMap.getLatestDate(group, true);

		byte[] dateBytes = cEngine.serialize(date);
		System.out.println("Date length: "+dateBytes.length);

		//extract and encrypt the file with the appropriat group key
		File file = new File(sourceFile);
		byte[] rawFile = null;
		try
		{
			rawFile = readFile(file);
		}
		catch(IOException e)
		{
			System.out.println(cEngine.formatAsError("Failed to read file"));
			return null;
		}
		byte[] encryptedFile = cEngine.AESEncrypt(rawFile, key);

		return append(encryptedFile,dateBytes);
	}

	public byte[] append(byte[] a, byte[] b)
	{
		//concatenate the date to the encrypted file
		byte[] c = new byte[a.length + b.length];
		System.arraycopy(b, 0, c, 0, b.length);
		System.arraycopy(a, 0, c, b.length, a.length);
		return c;
	}

	public static byte[] readFile (File file) throws IOException {
        // Open file
        RandomAccessFile f = new RandomAccessFile(file, "r");

        try 
        {
            // Get and check length
            long longlength = f.length();
            int length = (int) longlength;
            if (length != longlength) throw new IOException("File size >= 2 GB");

            // Read file and return data
            byte[] data = new byte[length];
            f.readFully(data);
            return data;
        }
        finally {
            f.close();
        }
    }

	private boolean recoverFileFromDownload(byte[] encryptedfile, File file, String group)
	{
		Date date = (Date)cEngine.deserialize(Arrays.copyOfRange(encryptedfile, 0, 46));
		System.out.println("\n"+groupFileKeyMap.toString());
		System.out.println("\ngroup being accessed: "+group);
		System.out.println("\ndate: "+date.toString());
		byte[] plainFile = cEngine.AESDecrypt(Arrays.copyOfRange(encryptedfile, 46, encryptedfile.length), groupFileKeyMap.getKeyFromNameAndDate(group, date, true));

		try
		{
			FileOutputStream out = new FileOutputStream(file);
			out.write(plainFile);
			out.close();
		}
		catch(Exception e)
		{
			System.out.println(cEngine.formatAsError("Exception when writing the file to disk"));		
		}

		return true;
	}
}

