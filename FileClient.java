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
		
		String userFile = userFolder+"FSKeys_" + userName + ".bin";
		
		if(setUpServer(server, userFile)==false)
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
			System.out.println("<< Recieving File Server Response: OK");
			System.out.println(cEngine.formatAsSuccess("Successfully deleted file: "+filename));				
		}
		else 
		{
			System.out.println(cEngine.formatAsError(env.getMessage()));
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
			    env.addObject(token);
			    env.addObject(sourceFile);
				System.out.println("\n>> Sending File Server Request: DOWNLOADF");
			    cEngine.writeAESEncrypted(env, aesKey, output);

						
				//retreive the incoming evelope
			    env = (Envelope)cEngine.readAESEncrypted(aesKey, input);
						    
				//read the body of the file one envelope at a time
				while (env.getMessage().compareTo("CHUNK")==0) 
				{ 
					fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));
					System.out.print(".");
					env = new Envelope("DOWNLOADF"); //Success
					cEngine.writeAESEncrypted(env, aesKey, output);
					env = (Envelope)cEngine.readAESEncrypted(aesKey, input);									
				}										
				fos.close();
						
				//when the end of file is detected, close and display the appropriate message
				if(env.getMessage().compareTo("EOF")==0) 
				{
					System.out.println("<< Recieving File Server Response: EOF");
				    fos.close();
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
				System.out.println("<< Recieving File Server Response: OK");
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
			
			 
			FileInputStream fis = new FileInputStream(sourceFile);
			 
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
			 
		 	//unless an error occurs, write the file in 4096 byte chunks
			do 
			{
				byte[] buf = new byte[4096];
				if (env.getMessage().compareTo("READY")!=0) 
				{
					System.out.println("READY EXPECTED");
					System.out.println(env.getMessage());
					return false;
				}
				message = new Envelope("CHUNK");
				int n = fis.read(buf); //can throw an IOException
				if (n <= 0) 
				{
					System.out.println(cEngine.formatAsError("Read error"));
					return false;
				}
					
				message.addObject(buf);
				message.addObject(new Integer(n));
					
				cEngine.writeAESEncrypted(message, aesKey, output);
						
				env = (Envelope)cEngine.readAESEncrypted(aesKey, input);
	        	System.out.println(cEngine.formatAsSuccess("chunk sent..."));
			 }
			 while (fis.available()>0);		 
					 
			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 { 
				
				//tell the sever we're done
				message = new Envelope("EOF");
				cEngine.writeAESEncrypted(message, aesKey, output);
	        	System.out.println(cEngine.formatAsSuccess("EOF sent"));
				
				env = (Envelope)cEngine.readAESEncrypted(aesKey, input);
				if(env.getMessage().compareTo("OK")==0) 
				{
					System.out.println("<< Recieving File Server Response: OK");
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

}

