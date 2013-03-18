/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

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
public class FileThread extends ServerThread
{
	private FileServer my_fs;

	public FileThread(FileServer _fs, Socket _socket)
	{
		super((Server)_fs, _socket);
		my_fs = _fs;
	}

	public void run()
	{
		String serverFolder = my_fs.name+"_Server_Resources/";
		String resourceFile = serverFolder+"FileResources.bin";

		boolean proceed = true;
		try
		{
			Envelope response = null;

//--SET UP CONNECTION------------------------------------------------------------------------------------------------
			System.out.println("\n*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + " ***");
			if(setUpConection() == false)
			{
				System.out.println("\n!!! Setup Failed: " + socket.getInetAddress() + ":" + socket.getPort() + " !!!");
				return;
			}
			System.out.println("\n*** Setup Finished: " + socket.getInetAddress() + ":" + socket.getPort() + " ***");
			
//----------------------------------------------------------------------------------------------------------------------
//-- REQUEST HANDLING LOOP
//----------------------------------------------------------------------------------------------------------------------
			//handle messages from the input stream(ie. socket)
			do
			{
				Envelope envelope = (Envelope)cEngine.readAESEncrypted(aesKey, input);
				System.out.println("\nRequest received: " + envelope.getMessage());

				// Handler to list files that this user is allowed to see
//--LIST FILES---------------------------------------------------------------------------------------------------------
				
				if(envelope.getMessage().equals("LFILES"))
				{

					if(envelope.getObjContents().size() < 1)
					{
						response = genAndPrintErrorEnvelope("Not enough data sent");
					}
					else
					{
						if(envelope.getObjContents().get(0) == null) 
						{
							response = genAndPrintErrorEnvelope("Token missing");
						}
						else
						{
							//retrieve the contents of the envelope
							UserToken yourToken = (UserToken)envelope.getObjContents().get(0); //Extract token

							//validate token, terminate connection if failed
							proceed = yourToken.verifySignature(my_fs.signVerifyKey, cEngine);
	        				System.out.println(cEngine.formatAsSuccess("Token Authenticated:"+proceed));
							if(!proceed) rejectToken(response, output);

							ArrayList<ShareFile> theFiles = FileServer.fileList.getFiles();
							if(theFiles.size() > 0)
							{
								response = new Envelope("OK");//success (check FileClient line 140 to see why this is the message
								response.addObject(theFiles);//See FileClient for protocol
								
								cEngine.writeAESEncrypted(response, aesKey, output);
								System.out.println(cEngine.formatAsSuccess("File list sent"));
							}
							else	//no files exist
							{
								System.out.println(cEngine.formatAsError("No files exist"));
								response = new Envelope("FAIL -- no files exist. ");
								cEngine.writeAESEncrypted(response, aesKey, output);
							}
						}
					}
				}

//--UPLOAD FILE--------------------------------------------------------------------------------------------------------
				
				if(envelope.getMessage().equals("UPLOADF"))
				{
					if(envelope.getObjContents().size() < 3)
					{
						response = genAndPrintErrorEnvelope("Not enough data sent");
					}
					else
					{
						if(envelope.getObjContents().get(0) == null) 
						{
							response = genAndPrintErrorEnvelope("bad path");
						}
						if(envelope.getObjContents().get(1) == null) 
						{
							response = genAndPrintErrorEnvelope("bad group");
						}
						if(envelope.getObjContents().get(2) == null) 
						{
							response = genAndPrintErrorEnvelope("bad token");
						}
						else {
							//retrieve the contents of the envelope
							String remotePath = (String)envelope.getObjContents().get(0);
							String group = (String)envelope.getObjContents().get(1);
							UserToken yourToken = (UserToken)envelope.getObjContents().get(2); //Extract token

							//validate token, terminate connection if failed
							proceed = yourToken.verifySignature(my_fs.signVerifyKey, cEngine);
	        				System.out.println(cEngine.formatAsSuccess("Token Authenticated:"+proceed));
							
							if(!proceed) rejectToken(response, output);

							if (FileServer.fileList.checkFile(remotePath)) 
							{
								response = genAndPrintErrorEnvelope("File already exists");
							}
							else if (!yourToken.getGroups().contains(group)) 
							{
								response = genAndPrintErrorEnvelope("Token does not have permissions for group: " + group);
							}
							//create file and handle upload
							else  
							{
								System.out.println(serverFolder+"shared_files/" + remotePath.replace('/', '_'));
								File file = new File(serverFolder+"shared_files/" + remotePath.replace('/', '_'));
								file.createNewFile();
								FileOutputStream fos = new FileOutputStream(file);
								System.out.printf("%sSuccessfully created file %s\n", cEngine.formatAsSuccess(""), remotePath.replace('/', '_'));

								//request file contents
								response = new Envelope("READY"); //Success
								cEngine.writeAESEncrypted(response, aesKey, output);

								//recieve and write the file to the directory
								envelope = (Envelope)input.readObject();
								while (envelope.getMessage().compareTo("CHUNK") == 0) 
								{
									fos.write((byte[])envelope.getObjContents().get(0), 0, (Integer)envelope.getObjContents().get(1));
									response = new Envelope("READY"); //Success
									cEngine.writeAESEncrypted(response, aesKey, output);
									envelope = (Envelope)input.readObject();
								}

								//end of file identifier expected, inform the user of status
								if(envelope.getMessage().compareTo("EOF") == 0) 
								{
									System.out.printf("%sTransfer successful file %s\n", cEngine.formatAsSuccess(""), remotePath);
									FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
									response = new Envelope("OK"); //Success
								}
								else 
								{
									response = genAndPrintErrorEnvelope("Failed to read the file  from the client: "+remotePath); //Success
								}
								fos.close();
							}
						}
					}

					cEngine.writeAESEncrypted(response, aesKey, output);
				}
//--DOWNLOAD FILE------------------------------------------------------------------------------------------------------
				else if (envelope.getMessage().compareTo("DOWNLOADF") == 0) 
				{
					//retrieve the contents of the envelope, and attampt to access the requested file
					String remotePath = (String)envelope.getObjContents().get(0);
					UserToken t = (UserToken)envelope.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/" + remotePath);

					//validate token, terminate connection if failed
					proceed = t.verifySignature(my_fs.signVerifyKey, cEngine);
	        		System.out.println(cEngine.formatAsSuccess("Token Authenticated:"+proceed));
					if(!proceed) rejectToken(response, output);

					if (sf == null) 
					{
						cEngine.writeAESEncrypted(genAndPrintErrorEnvelope("File ("+remotePath+") does not exist"), aesKey, output);
					}
					else if (!t.getGroups().contains(sf.getGroup()))
					{
						cEngine.writeAESEncrypted(genAndPrintErrorEnvelope("Token does not have permissions for group: " + sf.getGroup()), aesKey, output);
					}
					else 
					{
						try
						{
							System.out.println(serverFolder+"shared_files/_" + remotePath.replace('/', '_'));
							//try to grab the file
							File f = new File(serverFolder+"shared_files/_" + remotePath.replace('/', '_'));
							if (!f.exists()) 
							{
								cEngine.writeAESEncrypted(genAndPrintErrorEnvelope("file ("+remotePath.replace('/', '_')+") missing from disk:"), aesKey, output);
							}
							else 
							{
								FileInputStream fis = new FileInputStream(f);

								//send the file in 4096 byte chunks
								do 
								{
									byte[] buf = new byte[4096];
									if (envelope.getMessage().compareTo("DOWNLOADF") != 0) 
									{
										System.out.printf("%sServer error: %s\n", cEngine.formatAsError(""), envelope.getMessage());
										break;
									}
									envelope = new Envelope("CHUNK");
									int n = fis.read(buf); //can throw an IOException
									if (n > 0) 
									{
										System.out.printf(".");
									} 
									else if (n < 0) 
									{
										System.out.println(cEngine.formatAsError("Read error"));
									}

									//tack the chunk onto the envelope and write it
									envelope.addObject(buf);
									envelope.addObject(new Integer(n));
									cEngine.writeAESEncrypted(envelope, aesKey, output);

									//get response
									envelope = (Envelope)input.readObject();
								}
								while (fis.available() > 0);

								//If server indicates success, return the member list
								if(envelope.getMessage().compareTo("DOWNLOADF") == 0)
								{
									//send the end of file identifier
									envelope = new Envelope("EOF");
									cEngine.writeAESEncrypted(envelope, aesKey, output);

									//accept response
									envelope = (Envelope)input.readObject();
									if(envelope.getMessage().compareTo("OK") == 0) 
									{
										System.out.printf(cEngine.formatAsSuccess("File transfer successful\n"));
									}
									else 
									{
										System.out.println(cEngine.formatAsError("Transfer failed: " + envelope.getMessage()));
									}
								}
								else 
								{
									System.out.println(cEngine.formatAsError("Transfer failed: " + envelope.getMessage()));
								}
							}
						}
						catch(Exception ex)
						{
							System.out.println(cEngine.formatAsError("error during file sending"));
							/*System.err.println("Error: " + ex.getMessage());
							ex.printStackTrace(System.err);*/

							//NOTE: should we be sending a message here?

						}
					}
				}
//--DELETE FILE--------------------------------------------------------------------------------------------------------
				else if (envelope.getMessage().compareTo("DELETEF")==0) 
				{
					//retrieve the contents of the envelope, and attampt to access the requested file
					String remotePath = (String)envelope.getObjContents().get(0);
					UserToken t = (UserToken)envelope.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					
					//validate token, terminate connection if failed
					proceed = t.verifySignature(my_fs.signVerifyKey, cEngine);
	        		System.out.println(cEngine.formatAsSuccess("Token Authenticated:"+proceed));
					if(!proceed) rejectToken(response, output);

					if (sf == null) 
					{	
						envelope = genAndPrintErrorEnvelope("File (" + remotePath + ") does not exist");
					}
					else if (!t.getGroups().contains(sf.getGroup()))
					{
						envelope = genAndPrintErrorEnvelope("Token does not have permissions for group: " + sf.getGroup());
					}
					else 
					{
						//attempt to delete the file
						try
						{
							System.out.println(serverFolder+"shared_files/_" + remotePath.replace('/', '_'));
							File f = new File(serverFolder+"shared_files/_" + remotePath.replace('/', '_'));

							if (!f.exists()) 
							{
								envelope = genAndPrintErrorEnvelope("file ("+remotePath.replace('/', '_')+") missing from disk:");
							}
							else if (f.delete()) 
							{
								System.out.println(cEngine.formatAsSuccess("File ("+remotePath.replace('/', '_')+") deleted from disk"));
								FileServer.fileList.removeFile("/"+remotePath);
								envelope = new Envelope("OK");
							}
							else 
							{
								envelope = genAndPrintErrorEnvelope("Failure deleting file ("+remotePath.replace('/', '_')+")from disk. ");
							}


						}
						catch(Exception e1)
						{
							/*System.err.println("Error: " + e1.getMessage());
							e1.printStackTrace(System.err);
							envelope = new Envelope(e1.getMessage());*/
							envelope =  genAndPrintErrorEnvelope("Exception thrown. file ("+remotePath.replace('/', '_')+") may not exist");
						}


					}
					cEngine.writeAESEncrypted(envelope, aesKey, output);

				}
				else if(envelope.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
	        		System.out.println(cEngine.formatAsSuccess("Disconnected"));
					System.out.println("\n*** Disconnected: " + socket.getInetAddress() + ":" + socket.getPort() + " ***");
				}
			} while(proceed);
		}
		catch(Exception ex)
		{
			System.err.println("Error: " + ex.getMessage());
			ex.printStackTrace(System.err);
		}
	}
	
	private void rejectToken(Envelope response, ObjectOutputStream output)
	{

		response = new Envelope("ERROR: Token signature Rejected");
		response.addObject(null);
		cEngine.writeAESEncrypted(response, aesKey, output);
		try
		{
			socket.close();
		}
		catch(Exception ex)
		{
			System.out.println("WARNING: GroupThread; socket could not be closed");
		}
	}
}
