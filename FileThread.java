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
public class FileThread extends Thread
{
	private final Socket socket;
	private FileServer my_fs;
	private CryptoEngine cEngine;
	private AESKeySet aesKey;

	public FileThread(FileServer _fs, Socket _socket)
	{
		my_fs = _fs;
		socket = _socket;
		cEngine = new CryptoEngine();
	}

	public void run()
	{
		String serverFolder = my_fs.name+"_Server_Resources/";

		boolean proceed = true;
		try
		{
			//setup IO streams to bind with the sockets
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
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
				System.out.println("     *public key sent");
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
					response = new Envelope("FAIL -- not enough data. ");
					message = (Envelope)readObject(input);
					System.exit(-1);
				}
				else
				{
					if(message.getObjContents().get(0) == null) 
					{
						response = new Envelope("FAIL -- Token. ");
						message = (Envelope)readObject(input);
						System.exit(-1);
					}
					else
					{
						//retrieve the contents of the envelope
						UserToken yourToken = (UserToken)message.getObjContents().get(0); //Extract token

						//validate token, terminate connection if failed
						proceed = yourToken.verifySignature(my_fs.signVerifyKey, cEngine);
	        			  System.out.println("     *Token Authenticated:"+proceed);
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

				System.out.println("     *AES keyset recieved and stored");
				
//--CHALLENGE---------------------------------------------------------------------------------------------------------
				//THE AES KEY IS NOW SET
				message = (Envelope)readObject(input);
				if(message.getMessage().equals("CHALLENGE"));
				{
				System.out.println("\nRequest received: " + message.getMessage());
					//check packet integrity and token signature
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL -- not enough data. ");
						message = (Envelope)readObject(input);
						System.exit(-1);
					}
					else
					{
						if(message.getObjContents().get(0) == null) 
						{
							response = new Envelope("FAIL -- Token. ");
							message = (Envelope)readObject(input);
							System.exit(-1);
						}
						else
						{
							//retrieve the contents of the envelope
							UserToken yourToken = (UserToken)message.getObjContents().get(0); //Extract token

							//validate token, terminate connection if failed
							proceed = yourToken.verifySignature(my_fs.signVerifyKey, cEngine);
		        			 System.out.println("     *Token Authenticated:"+proceed);
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
					System.out.println("     *Challenge answered");
				}
			}
			else
			{
				System.out.println("     !Failed to setup AES key");
				System.exit(-1);
			}
			
			System.out.println("\n*** Setup Finished: " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			
//---------------------------------------------------------------------------------------------------------------------
//-- END SETUP, BEGIN LOOP
//---------------------------------------------------------------------------------------------------------------------
			//handle messages from the input stream(ie. socket)
			do
			{
				Envelope e = (Envelope)input.readObject();
				System.out.println("\nRequest received: " + e.getMessage());

				// Handler to list files that this user is allowed to see
//--LIST FILES---------------------------------------------------------------------------------------------------------
				
				if(e.getMessage().equals("LFILES"))
				{

					if(e.getObjContents().size() < 1)
					{
						response = new Envelope("FAIL -- not enough data. ");
					}
					else
					{
						if(e.getObjContents().get(0) == null) 
						{
							response = new Envelope("FAIL -- Token. ");
						}
						else
						{
							//retrieve the contents of the envelope
							UserToken yourToken = (UserToken)e.getObjContents().get(0); //Extract token

							//validate token, terminate connection if failed
							proceed = yourToken.verifySignature(my_fs.signVerifyKey, cEngine);
	        				System.out.println("     *Token Authenticated:"+proceed);
							if(!proceed) rejectToken(response, output);

							ArrayList<ShareFile> theFiles = FileServer.fileList.getFiles();
							if(theFiles.size() > 0)
							{
								response = new Envelope("OK");//success (check FileClient line 140 to see why this is the message
								response.addObject(theFiles);//See FileClient for protocol
								
								output.writeObject(response);
								System.out.println("     *File list sent");
							}
							else	//no files exist
							{
								System.out.println("     !No files exist");
								response = new Envelope("FAIL -- no files exist. ");
								output.writeObject(response);
							}
						}
					}
				}

//--UPLOAD FILE--------------------------------------------------------------------------------------------------------
				
				if(e.getMessage().equals("UPLOADF"))
				{
					if(e.getObjContents().size() < 3)
					{
						System.out.println("     !Message too small");
						response = new Envelope("FAIL -- bad contents. ");
					}
					else
					{
						if(e.getObjContents().get(0) == null) 
						{
							System.out.println("     !Bad path");
							response = new Envelope("FAIL -- bad path. ");
						}
						if(e.getObjContents().get(1) == null) 
						{
							System.out.println("     !Bad group");
							response = new Envelope("FAIL -- bad group. ");
						}
						if(e.getObjContents().get(2) == null) 
						{
							System.out.println("     !bad token");
							response = new Envelope("FAIL -- bad token. ");
						}
						else {
							//retrieve the contents of the envelope
							String remotePath = (String)e.getObjContents().get(0);
							String group = (String)e.getObjContents().get(1);
							UserToken yourToken = (UserToken)e.getObjContents().get(2); //Extract token

							//validate token, terminate connection if failed
							proceed = yourToken.verifySignature(my_fs.signVerifyKey, cEngine);
	        				  System.out.println("     *Token Authenticated:"+proceed);
							if(!proceed) rejectToken(response, output);

							if (FileServer.fileList.checkFile(remotePath)) 
							{
								System.out.printf("     !File already exists at %s\n", remotePath);
								response = new Envelope("FAIL -- file already exists. "); //Success
							}
							else if (!yourToken.getGroups().contains(group)) 
							{
								System.out.printf("     !User missing valid token for group %s\n", group);
								response = new Envelope("FAIL -- unauthorized user token for group. "); //Success
							}
							//create file and handle upload
							else  
							{
	System.out.println(serverFolder+"shared_files/" + remotePath.replace('/', '_'));
								File file = new File(serverFolder+"shared_files/" + remotePath.replace('/', '_'));
								file.createNewFile();
								FileOutputStream fos = new FileOutputStream(file);
								System.out.printf("     *Successfully created file %s\n", remotePath.replace('/', '_'));

								//request file contents
								response = new Envelope("READY"); //Success
								output.writeObject(response);

								//recieve and write the file to the directory
								e = (Envelope)input.readObject();
								while (e.getMessage().compareTo("CHUNK") == 0) 
								{
									fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
									response = new Envelope("READY"); //Success
									output.writeObject(response);
									e = (Envelope)input.readObject();
								}

								//end of file identifier expected, inform the user of status
								if(e.getMessage().compareTo("EOF") == 0) 
								{
									System.out.printf("     *Transfer successful file %s\n", remotePath);
									FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
									response = new Envelope("OK"); //Success
								}
								else 
									{
									System.out.printf("     *Failed to read filee %s from client\n", remotePath);
									response = new Envelope("ERROR -- failed attempt at reading file from client. "); //Success
								}
								fos.close();
							}
						}
					}

					output.writeObject(response);
				}
//--DOWNLOAD FILE------------------------------------------------------------------------------------------------------
				else if (e.getMessage().compareTo("DOWNLOADF") == 0) 
				{
					//retrieve the contents of the envelope, and attampt to access the requested file
					String remotePath = (String)e.getObjContents().get(0);
					UserToken t = (UserToken)e.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/" + remotePath);

					//validate token, terminate connection if failed
					proceed = t.verifySignature(my_fs.signVerifyKey, cEngine);
	        		  System.out.println("     *Token Authenticated:"+proceed);
					if(!proceed) rejectToken(response, output);

					if (sf == null) 
					{
						System.out.printf("     !File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR -- file missing. ");
						output.writeObject(e);
					}
					else if (!t.getGroups().contains(sf.getGroup()))
					{
						System.out.printf("     !user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR -- insufficient user permissions. ");
						output.writeObject(e);
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
								System.out.printf("     !file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR -- file not on disk. ");
								output.writeObject(e);
							}
							else 
							{
								FileInputStream fis = new FileInputStream(f);

								//send the file in 4096 byte chunks
								do 
								{
									byte[] buf = new byte[4096];
									if (e.getMessage().compareTo("DOWNLOADF") != 0) 
									{
										System.out.printf("     !Server error: %s\n", e.getMessage());
										break;
									}
									e = new Envelope("CHUNK");
									int n = fis.read(buf); //can throw an IOException
									if (n > 0) 
									{
										System.out.printf(".");
									} 
									else if (n < 0) 
									{
										System.out.println("     !Read error");
									}

									//tack the chunk onto the envelope and write it
									e.addObject(buf);
									e.addObject(new Integer(n));
									output.writeObject(e);

									//get response
									e = (Envelope)input.readObject();
								}
								while (fis.available() > 0);

								//If server indicates success, return the member list
								if(e.getMessage().compareTo("DOWNLOADF") == 0)
								{
									//send the end of file identifier
									e = new Envelope("EOF -- end of file. ");
									output.writeObject(e);

									//accept response
									e = (Envelope)input.readObject();
									if(e.getMessage().compareTo("OK") == 0) 
									{
										System.out.printf("     *File transfer successful\n");
									}
									else 
									{
										System.out.printf("     !transfer failed: %s\n", e.getMessage());
									}
								}
								else 
								{

									System.out.printf("     !transfer failed: %s\n", e.getMessage());
								}
							}
						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e.getMessage());
							e1.printStackTrace(System.err);

						}
					}
				}
//--DELETE FILE--------------------------------------------------------------------------------------------------------
				else if (e.getMessage().compareTo("DELETEF")==0) 
				{
					//retrieve the contents of the envelope, and attampt to access the requested file
					String remotePath = (String)e.getObjContents().get(0);
					UserToken t = (UserToken)e.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					
					//validate token, terminate connection if failed
					proceed = t.verifySignature(my_fs.signVerifyKey, cEngine);
	        		System.out.println("     *Token Authenticated:"+proceed);
					if(!proceed) rejectToken(response, output);


					if (sf == null) 
					{	
						System.out.printf("     !File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR -- file does not exists. ");
					}
					else if (!t.getGroups().contains(sf.getGroup()))
					{
						System.out.printf("     !user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR -- insufficient user permissions. ");
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
								System.out.printf("     !file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR -- insufficient user permissions. ");
							}
							else if (f.delete()) 
							{
								System.out.printf("     *File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
								FileServer.fileList.removeFile("/"+remotePath);
								e = new Envelope("OK");
							}
							else 
							{
								System.out.printf("     !Failure deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR -- file unable to be deleted from disk. ");
							}


						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e1.getMessage());
							e1.printStackTrace(System.err);
							e = new Envelope(e1.getMessage());
						}


					}
					output.writeObject(e);

				}
				else if(e.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
	        		System.out.println("     *Disconnected");
					System.out.println("\n*** Disconnected: " + socket.getInetAddress() + ":" + socket.getPort() + "***");
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
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
		catch(Exception e)
		{
			e.printStackTrace();
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
		catch(Exception e)
		{
			e.printStackTrace();
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
		catch(Exception e)
		{
			System.out.println("WARNING: GroupThread; socket could not be closed");
		}
	}
}
