/* This thread does all the work. It communicates with the client through Envelopes.
 * 
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

public class GroupThread extends Thread 
{
	private final Socket socket;
	private GroupServer my_gs;
	private CryptoEngine cEngine;
	private AESKeySet aesKey = null;
	
	//These get spun off from GroupServer
	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
		cEngine = my_gs.cEngine;
	}
	
	public void run()
	{
		boolean proceed = true;
		
		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
//--SET UP AES KEY-------------------------------------------------------------------------------------------------------------
			boolean keyNeedsSet = true;
			
			setKey(input, output);
			assert aesKey != null;
			
			//handle messages from the input stream(ie. socket)
			do
			{
				Envelope message = (Envelope)readObject(input);
				System.out.println("Request received: " + message.getMessage());
				Envelope response = null;
				
//--GET TOKEN---------------------------------------------------------------------------------------------------------
				if(message.getMessage().equals("GET"))//Client wants a token
				{
					String username = (String)message.getObjContents().get(0); //Get the username
					String pwd = (String)message.getObjContents().get(1);//get password
					if(username == null)
					{
						response = new Envelope("FAIL: no username provided.");
						writeObject(output, response);
					}
					else if(!my_gs.userList.checkUser(username))
					{
						response = new Envelope("FAIL: username not found.");
						writeObject(output, response);
					}
					else if(pwd == null || pwd.length() == 0)
					{
						response = new Envelope("FAIL: no password.");
						writeObject(output, response);
					}
					else if(!my_gs.userList.getUserPassword(username).equals(pwd))
					{
						response = new Envelope("Wrong password.");
						writeObject(output, response);
					}
					else
					{
						UserToken yourToken = createToken(username); //Create a token

						//validate token, terminate connection if failed
						proceed = yourToken.verifySignature(my_gs.signKeys.getPublic(), cEngine);
						if(!proceed) rejectToken(response, output);
						
						//Respond to the client. On error, the client will receive a null token
						response = new Envelope("OK");
						response.addObject(yourToken);
						writeObject(output, response);
					}
				}
//--CREATE USER-------------------------------------------------------------------------------------------------------
				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL: user unable to be created -- message object size less than 2. ");
					}
					else
					{
						response = new Envelope("FAIL: user unable to be created. ");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null && message.getObjContents().get(2) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								String pwd = (String)message.getObjContents().get(2);
								
								//validate token, terminate connection if failed
								proceed = yourToken.verifySignature(my_gs.signKeys.getPublic(), cEngine);
								if(!proceed) rejectToken(response, output);

								//create the user if the username/token allow it
								if(createUser(username, pwd, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					writeObject(output, response);
				}
//--DELETE USER---------------------------------------------------------------------------------------------------------
				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{					
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL: user unable to be deleted -- message object size less than 2. ");
					}
					else
					{
						response = new Envelope("FAIL: user unable to be deleted. ");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

								//validate token, terminate connection if failed
								proceed = yourToken.verifySignature(my_gs.signKeys.getPublic(), cEngine);
								if(!proceed) rejectToken(response, output);
								
								if(isAdmin(yourToken))
								{
									if (my_gs.userList.allUsers().contains(username))
									{
										my_gs.deleteUser(username);
										response = new Envelope("OK");
									}
									else response = new Envelope("FAIL: user unable to be deleted -- username not found. ");
								}
								else response = new Envelope("FAIL: user unable to be deleted -- you do not have sufficient privileges. ");
							}
						}
					}
					writeObject(output, response);
				}
//--CREATE GROUP---------------------------------------------------------------------------------------------------------
				else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
				{
					//if the message is too short, return failure
					response = new Envelope("FAIL: group unable to be created. ");
					if(message.getObjContents().size() > 1)
					{
						//get the elements of the message
						if(message.getObjContents().get(0) != null && message.getObjContents().get(1) != null)
						{
							String groupName = (String)message.getObjContents().get(0); //Extract the group name
							UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

							//validate token, terminate connection if failed
							proceed = yourToken.verifySignature(my_gs.signKeys.getPublic(), cEngine);
							if(!proceed) rejectToken(response, output);

							//create the group if the it doesn't already exist
							if(createGroup(groupName, yourToken))
							{
								response = new Envelope("OK"); //Success
							}
						}
					}
					writeObject(output, response);
				}
//--DELETE GROUP--------------------------------------------------------------------------------------------------------
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
					//if the message is too short, return failure
					response = new Envelope("FAIL: group unable to be deleted. ");
					if(message.getObjContents().size() > 1)
					{
						//get the elements of the message
						if(message.getObjContents().get(0) != null && message.getObjContents().get(1) != null)
						{
							String groupName = (String)message.getObjContents().get(0); //Extract the group name
							UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

							//validate token, terminate connection if failed
							proceed = yourToken.verifySignature(my_gs.signKeys.getPublic(), cEngine);
							if(!proceed) rejectToken(response, output);
								
							//create the group if the it doesn't already exist
							if(deleteGroup(groupName, yourToken))
							{
								response = new Envelope("OK"); //Success
							}
							else response = new Envelope("FAIL: group unable to be deleted. ");
						}
					}
					writeObject(output, response);
				}
//--LIST MEMBERS--------------------------------------------------------------------------------------------------------
				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{
					//if the message is too short, return failure
					response = new Envelope("FAIL: user list unable to be generated. ");
					if(message.getObjContents().size() > 1)
					{
						//get the elements of the message
						if(message.getObjContents().get(0) != null && message.getObjContents().get(1) != null)
						{
							String groupName = (String)message.getObjContents().get(0); //Extract the group name
							UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

							//validate token, terminate connection if failed
							proceed = yourToken.verifySignature(my_gs.signKeys.getPublic(), cEngine);
							if(!proceed) rejectToken(response, output);

							ArrayList<String> users = listMembers(groupName, yourToken);
							if(users != null && users.size() > 0)
							{
								response = new Envelope("OK");
								response.addObject(users);
							}
							else//no files exist
							{
								response = new Envelope("FAIL -- no users detected. ");
							}
					
						}
					}
					writeObject(output, response);
				}
//--ADD TO GROUP--------------------------------------------------------------------------------------------------------
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
					//if the message is too short, return failure
					response = new Envelope("FAIL -- user unable to be added to group. ");
					if(message.getObjContents().size() > 2)
					{
						//get the elements of the message
						if(message.getObjContents().get(0) != null && message.getObjContents().get(1) != null)
						{
							String userName = (String)message.getObjContents().get(0); //Extract the user name
							String groupName = (String)message.getObjContents().get(1); //Extract the group name
							UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the token

							//validate token, terminate connection if failed
							proceed = yourToken.verifySignature(my_gs.signKeys.getPublic(), cEngine);
							if(!proceed) rejectToken(response, output);

							//verify the owner
							if(my_gs.groupList.getGroupOwners(groupName).contains(yourToken.getSubject()))
							{
								//create the group if the it doesn't already exist
								if(addToGroup(userName, groupName, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
					
						}
					}		
					writeObject(output, response);
				}
//--REMOVE FROM GROUP----------------------------------------------------------------------------------------------------
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
					//if the message is too short, return failure
					response = new Envelope("FAIL -- unable to remove user from group. ");
					if(message.getObjContents().size() > 1)
					{
						//get the elements of the message
						if(message.getObjContents().get(0) != null && message.getObjContents().get(1) != null)
						{
							String userName = (String)message.getObjContents().get(0); //Extract the user name
							String groupName = (String)message.getObjContents().get(1); //Extract the group name
							UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the token

							//validate token, terminate connection if failed
							proceed = yourToken.verifySignature(my_gs.signKeys.getPublic(), cEngine);
							if(!proceed) rejectToken(response, output);

							//verify the owner
							if(my_gs.groupList.getGroupOwners(groupName).contains(yourToken.getSubject()))
							{
								//create the group if the it doesn't already exist
								if(removeFromGroup(userName, groupName, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
					
						}
					}
					writeObject(output, response);
				}
				
//--SEE ALL USERS----------------------------------------------------------------------------------------------------
				else if(message.getMessage().equals("ALLUSERS")) //Admin wants to see all of the users in existence
				{
					response = new Envelope("FAIL -- complete user list unable to be generated. ");
					if(message.getObjContents() != null)
					{
						UserToken theirToken = (UserToken)message.getObjContents().get(0);

						//validate token, terminate connection if failed
						proceed = theirToken.verifySignature(my_gs.signKeys.getPublic(), cEngine);
						if(!proceed) rejectToken(response, output);

						if(isAdmin(theirToken))//test if they are an admin
						{
							response = new Envelope("OK");
							ArrayList<String> usernameList = my_gs.userList.allUsers();
							response.addObject(usernameList);
						}
					}
					writeObject(output, response);
				}
//--DISCONNECT----------------------------------------------------------------------------------------------------------
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}
				else
				{
					response = new Envelope("FAIL -- server does not understand client request. "); //Server does not understand client request
					writeObject(output, response);
				}
			}
			while(proceed);	
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	//Method to write objects
	private boolean writeObject(ObjectOutputStream output, Object obj)
	{
		try
		{
			ByteArrayOutputStream toBytes = new ByteArrayOutputStream();//create ByteArrayOutputStream
			ObjectOutputStream localOutput = new ObjectOutputStream(toBytes);//Make an object outputstream to that bytestream
			localOutput.writeObject(obj);//write to the bytearrayoutputstream
			byte[] data = toBytes.toByteArray();//turn our object into byte[]
			
			byte[] eData = cEngine.AESEncrypt(data, aesKey);//encrypt the data
			output.writeObject(eData);//write the data to the client
			toBytes.close();
			localOutput.close();
		}
		catch(Exception e)
		{
			e.printStackTrace();
			return false;
		}
		return true;
	}
	
	//Method to read objects
	private Object readObject(ObjectInputStream input)
	{
		Object obj = null;
		try
		{
			byte[] eData = (byte[])input.readObject();
			byte[] data = cEngine.AESDecrypt(eData, aesKey);
			ByteArrayInputStream fromBytes = new ByteArrayInputStream(data);
			ObjectInputStream localInput = new ObjectInputStream(fromBytes);
			obj = localInput.readObject();
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
		
		return obj;
	}
	
	//Method to receive and establish an AESKey from the client
	private boolean setKey(ObjectInputStream input, ObjectOutputStream output)
	{
		try
		{
			Key rsaSessionPublic = my_gs.authKeys.getPublic();
			Key rsaSessionPrivate = my_gs.authKeys.getPrivate();
			//These keys exist just to encrypt/decrypt this specific session key for this user
			
			Envelope message;
			Envelope response;
			message = (Envelope)input.readObject();
			System.out.println("Request received: " + message.getMessage());
			if(message.getMessage().equals("PUBKEYREQ"))
			{
				response = new Envelope("PUBKEYANSW");
				response.addObject(rsaSessionPublic);//send as Key not byte[]
				output.writeObject(response);
				
				message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				if(message.getMessage().equals("AESKEY"))
				{
					byte[] aesKeyBytes = (byte[]) message.getObjContents().get(0);//This is sent as byte[]

					byte[] aesKeyBytesA = new byte[128];
					byte[] aesKeyBytesB = new byte[128];
					
					System.arraycopy(aesKeyBytes, 0, aesKeyBytesA, 0, 128);
					System.arraycopy(aesKeyBytes, 128, aesKeyBytesB, 0, 128);
				
					aesKeyBytesA = cEngine.RSADecrypt(aesKeyBytesA, rsaSessionPrivate);
					aesKeyBytesB = cEngine.RSADecrypt(aesKeyBytesB, rsaSessionPrivate);
					
					System.arraycopy(aesKeyBytesA, 0, aesKeyBytes, 0, 100);
					System.arraycopy(aesKeyBytesB, 0, aesKeyBytes, 100, 41);
					
					ByteArrayInputStream fromBytes = new ByteArrayInputStream(aesKeyBytes);
					ObjectInputStream localInput = new ObjectInputStream(fromBytes);
					aesKey = new AESKeySet((Key) localInput.readObject(), new IvParameterSpec((byte[])message.getObjContents().get(1)));
					//get(1) contains the IV. localinput turned the byte[] back into a key
					return true;
				}
				else {return false;}
			}
			else {return false;}
		}
		catch(Exception e)
		{
			e.printStackTrace();
			System.exit(-1);
		}
		return false;
	}
	
	//Method to create tokens
	private UserToken createToken(String username) 
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new token with server's name, user's name, and user's groups
			UserToken yourToken = new UserToken(my_gs.name, username, my_gs.userList.getUserGroups(username));

			//sign the token
			yourToken.sign(my_gs.signKeys.getPrivate(), cEngine);
			
			return yourToken;
		}
		else
		{
			return null;
		}
	}
	
	
	//Method to check user is admmin
	private boolean isAdmin(UserToken token)
	{
		String user = token.getSubject();
		ArrayList<String> temp = my_gs.userList.getUserGroups(user);
		if(temp.contains("ADMIN"))
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	
	//Method to create a user
	private boolean createUser(String username, String pwd, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administrator
			if(temp.contains("ADMIN"))
			{
				//Does user already exist?
				if(my_gs.userList.checkUser(username))
				{
					return false; //User already exists
				}
				else
				{
					my_gs.userList.addUser(username, pwd);
					return true;
				}
			}
			else
			{
				return false; //requester not an administrator
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}
	

//----------------------------------------------------------------------------------------------------------------------
//-- UTILITY FUNCITONS
//----------------------------------------------------------------------------------------------------------------------
	private boolean createGroup(String groupName, UserToken yourToken)
	{
		//Check if group exists
		if(!my_gs.groupList.checkGroup(groupName))
		{
			my_gs.createGroup(groupName, yourToken.getSubject());
			return true;
		}
		return false; //requester does not exist
	}

	private boolean deleteGroup(String groupName, UserToken yourToken)
	{
		//verify that the group exists, and that the user is an owner
		if(my_gs.groupList.checkGroup(groupName) && my_gs.groupList.getGroupOwners(groupName).contains(yourToken.getSubject()))
		{
			my_gs.deleteGroup(groupName);
			return true;
		}
		return false;
	}

	private ArrayList<String> listMembers(String groupName, UserToken yourToken)
	{
		ArrayList<String> members = null;
		//verify that the group exists, and that the user is an owner
		if(my_gs.groupList.checkGroup(groupName) && my_gs.groupList.getGroupOwners(groupName).contains(yourToken.getSubject()))
		{
			members = my_gs.groupList.getGroupMembers(groupName);
		}
		return members;
	}

	private boolean addToGroup(String userName, String groupName, UserToken yourToken)
	{
		//verify that the group exists, that the user is an owner, and that the user isnt already a member
		if(my_gs.groupList.checkGroup(groupName) && my_gs.groupList.getGroupOwners(groupName).contains(yourToken.getSubject()) && !my_gs.groupList.getGroupMembers(groupName).contains(userName))
		{
			my_gs.addUserToGroup(groupName, userName);
			return true;
		}
		return false;
	}

	private boolean removeFromGroup(String userName, String groupName, UserToken yourToken)
	{
		//verify that the group exists, and that the user is an owner
		if(my_gs.groupList.checkGroup(groupName) && my_gs.groupList.getGroupOwners(groupName).contains(yourToken.getSubject()))
		{
			my_gs.removeUserFromGroup(groupName, userName);
			return true;
		}
		return false;
	}

	private boolean disconnect(String userName, UserToken yourToken)
	{
		return false;
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
