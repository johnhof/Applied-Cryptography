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
		super(_socket);
		my_fs = _fs;
	}

	public void run()
	{
		String serverFolder = my_fs.name+"_Server_Resources/";

		boolean proceed = true;
		try
		{
			//setup IO streams to bind with the sockets
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + " ***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			Envelope response = null;

//---------------------------------------------------------------------------------------------------------------------
//-- BEGIN CONNECTION SETUP
//---------------------------------------------------------------------------------------------------------------------
			
//--RSA KEY REQUEST-----------------------------------------------------------------------------------------------------
			Envelope message = (Envelope)input.readObject();
			if(message.getMessage().equals("PUBKEYREQ"))
			{
				System.out.println("\nRequest received: " + message.getMessage());
				response = new Envelope("OK");
				response.addObject(my_fs.authKeys.getPublic());
				output.writeObject(response);
				System.out.println(cEngine.formatAsSuccess("public key sent"));
			}

//--RECIEVE AES KEY---------------------------------------------------------------------------------------------------

			//This is wrong, they are still sending this as an envelope
			message = (Envelope)input.readObject();
			//The Client has encrypted a message for us with our public key.
			if(message.getMessage().equals("AESKEY"))
			{
				System.out.println("\nRequest received: " + message.getMessage());
				//check packet integrity and token signature
				if(message.getObjContents().size() < 2)
				{
					response = genAndPrintErrorEnvelope("Not enough data");
					System.exit(-1);
				}
				else
				{
					if(message.getObjContents().get(0) == null) 
					{
						response = genAndPrintErrorEnvelope("Token missing");
						System.exit(-1);
					}
					else
					{
						//retrieve the contents of the envelope
						UserToken yourToken = (UserToken)message.getObjContents().get(0); //Extract token

						//validate token, terminate connection if failed
						proceed = yourToken.verifySignature(my_fs.signVerifyKey, cEngine);
	        			System.out.println(cEngine.formatAsSuccess("Token Authenticated:"+proceed));
						if(!proceed)
						{
							rejectToken(response, output);
							System.exit(-1);
						}
					}
				}

				byte[] aesKeyBytes = (byte[]) message.getObjContents().get(1);//This is sent as byte[]

				byte[] aesKeyBytesA = new byte[128];
				byte[] aesKeyBytesB = new byte[128];
					
				System.arraycopy(aesKeyBytes, 0, aesKeyBytesA, 0, 128);
				System.arraycopy(aesKeyBytes, 128, aesKeyBytesB, 0, 128);
				
				aesKeyBytesA = cEngine.RSADecrypt(aesKeyBytesA, my_fs.authKeys.getPrivate());
				aesKeyBytesB = cEngine.RSADecrypt(aesKeyBytesB, my_fs.authKeys.getPrivate());
					
				System.arraycopy(aesKeyBytesA, 0, aesKeyBytes, 0, 100);
				System.arraycopy(aesKeyBytesB, 0, aesKeyBytes, 100, 41);
					
				ByteArrayInputStream fromBytes = new ByteArrayInputStream(aesKeyBytes);
				ObjectInputStream localInput = new ObjectInputStream(fromBytes);
				aesKey = new AESKeySet((Key) localInput.readObject(), new IvParameterSpec((byte[])message.getObjContents().get(2)));
				//get(1) contains the IV. localinput turned the byte[] back into a key

				System.out.println(cEngine.formatAsSuccess("AES keyset recieved and stored"));
				
//--CHALLENGE---------------------------------------------------------------------------------------------------------
				//THE AES KEY IS NOW SET
				message = (Envelope)readObject(input);
				if(message.getMessage().equals("CHALLENGE"));
				{
				System.out.println("\nRequest received: " + message.getMessage());
					//check packet integrity and token signature
					if(message.getObjContents().size() < 2)
					{
						response = genAndPrintErrorEnvelope("Not enough data sent");
						System.exit(-1);
					}
					else
					{
						if(message.getObjContents().get(0) == null) 
						{
							response = genAndPrintErrorEnvelope("Token missing");
							System.exit(-1);
						}
						else
						{
							//retrieve the contents of the envelope
							UserToken yourToken = (UserToken)message.getObjContents().get(0); //Extract token

							//validate token, terminate connection if failed
							proceed = yourToken.verifySignature(my_fs.signVerifyKey, cEngine);
		        			 System.out.println(cEngine.formatAsSuccess("Token Authenticated:"+proceed));
							if(!proceed)
							{
								rejectToken(response, output);
								System.exit(-1);
							}
						}
					}
					Integer challenge = (Integer)message.getObjContents().get(1);
					challenge = new Integer((challenge.intValue()+1));
					response = new Envelope("OK");
					response.addObject(challenge);
					java.sql.Timestamp currentTime = new java.sql.Timestamp(Calendar.getInstance().getTime().getTime());
					response.addObject(currentTime);
					writeObject(output, response);
					System.out.println(cEngine.formatAsSuccess("Challenge answered"));
				}
			}
			else
			{
				System.out.println(cEngine.formatAsError("Failed to setup AES key"));
				System.exit(-1);
			}
			
			System.out.println("\n*** Setup Finished: " + socket.getInetAddress() + ":" + socket.getPort() + " ***");
			
//---------------------------------------------------------------------------------------------------------------------
//-- END SETUP, BEGIN LOOP
//---------------------------------------------------------------------------------------------------------------------
			//handle messages from the input stream(ie. socket)
			do
			{
				Envelope envelope = (Envelope)input.readObject();
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
								
								output.writeObject(response);
								System.out.println(cEngine.formatAsSuccess("File list sent"));
							}
							else	//no files exist
							{
								System.out.println(cEngine.formatAsError("No files exist"));
								response = new Envelope("FAIL -- no files exist. ");
								output.writeObject(response);
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
								output.writeObject(response);

								//recieve and write the file to the directory
								envelope = (Envelope)input.readObject();
								while (envelope.getMessage().compareTo("CHUNK") == 0) 
								{
									fos.write((byte[])envelope.getObjContents().get(0), 0, (Integer)envelope.getObjContents().get(1));
									response = new Envelope("READY"); //Success
									output.writeObject(response);
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

					output.writeObject(response);
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
						output.writeObject(genAndPrintErrorEnvelope("File ("+remotePath+") does not exist"));
					}
					else if (!t.getGroups().contains(sf.getGroup()))
					{
						output.writeObject(genAndPrintErrorEnvelope("Token does not have permissions for group: " + sf.getGroup()));
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
								envelope = genAndPrintErrorEnvelope("file ("+remotePath.replace('/', '_')+") missing from disk:");
								output.writeObject(envelope);
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
									output.writeObject(envelope);

									//get response
									envelope = (Envelope)input.readObject();
								}
								while (fis.available() > 0);

								//If server indicates success, return the member list
								if(envelope.getMessage().compareTo("DOWNLOADF") == 0)
								{
									//send the end of file identifier
									envelope = new Envelope("EOF");
									output.writeObject(envelope);

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
					output.writeObject(envelope);

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

	private Object readObject(ObjectInputStream input)
	{
		Object obj = null;
		try
		{
			byte[] eData = (byte[])input.readObject();
			byte[] data = cEngine.AESDecrypt(eData, aesKey);
			obj = cEngine.deserialize(data);
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		}
		
		return obj;
	}
	
	private boolean writeObject(ObjectOutputStream output, Object obj)
	{
		try
		{
			byte[] data = cEngine.serialize(obj);
			
			byte[] eData = cEngine.AESEncrypt(data, aesKey);//encrypt the data
			output.writeObject(eData);//write the data to the client
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
			return false;
		}
		return true;
	}
	
	private void rejectToken(Envelope response, ObjectOutputStream output)
	{

		response = new Envelope("ERROR: Token signature Rejected");
		response.addObject(null);
		writeObject(output, response);
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
