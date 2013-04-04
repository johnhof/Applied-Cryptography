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

public class GroupThread extends ServerThread 
{
	private GroupServer my_gs;
    private static final String salt = "c1d215a922ad186acbe436e6e2c513128b0aaa23ed6e3a4d48140b4931895384";
	protected GroupKeyMapController groupFileKeyMap;
	
	//These get spun off from GroupServer
	public GroupThread(Socket _socket, GroupServer _gs)
	{
		super((Server)_gs,_socket);
		my_gs = _gs;

		//grab/create the shared instance of our keymap
		groupFileKeyMap = GroupKeyMapController.getInstance(my_gs.name, my_gs.resourceFolder);
	}
	
	public void run()
	{
    	String groupFolder = "Group_Server_Resources/";
		String resourceFile = groupFolder+"GroupResources.rsc";

		try
		{

//--SET UP CONNECTION------------------------------------------------------------------------------------------------
			System.out.println("\n*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + " ***");
			if(setUpConnection() == false)
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
				System.out.println("\nWaiting for request...");
				Envelope message = (Envelope)cEngine.readAESEncrypted(aesKey, input);
				msgNumber++;
				System.out.println("\n<< ("+msgNumber+"): Request Received: " + message.getMessage());
				UserToken reqToken = null;

				Envelope response = new Envelope("OK"); // if no error occurs, send OK
				boolean error = true; //assume an error will occur
				String errorMsg = "Invalid request";
				
//--DISCONNECT----------------------------------------------------------------------------------------------------------
				
				//no data is required for disconnect, handle it first
				if(message.getMessage().equals("DISCONNECT"))
				{
					socket.close(); //Close the socket
					System.out.println(cEngine.formatAsSuccess("Disconnected"));
					System.out.println("\n*** Disconnected: " + socket.getInetAddress() + ":" + socket.getPort() + " ***");
					return;
				}

//--GET TOKEN------------------------------------------------------------------------------------------------------------
				
				else if(message.getMessage().equals("TOKEN"))//Client wants a token
				{
					getTokenHandler(message, response);
					continue;
				}

//--CHECK: TOKEN, MSGNUMBER, AND HMAC------------------------------------------------------------------------------------------------
					
				reqToken = checkMessagePreReqs(message, response, my_gs.signKeys.getPublic());	
				if(reqToken==null) return;

				//increment and attach the message number to the response
				response.addObject(msgNumber);

				//!!!! Everything this beyond point requires a valid token & message number !!!!

//--CREATE USER-------------------------------------------------------------------------------------------------------
				
				if(message.getMessage().equals("CUSER")) //Client wants to create a user
				{
					errorMsg = "Could not create user; ";

					if(message.getObjContents().size() >4)
					{
						String username = (String)message.getObjContents().get(2); //Extract the username
						String pwd = (String)message.getObjContents().get(3); //extract the password

						//attempt to create the use using the given credentials
						if(username != null && pwd != null && createUser(username, pwd, reqToken))
						{					
							System.out.println(cEngine.formatAsSuccess("User created"));
							error = false;
						}
						else errorMsg += "Check input before trying again";
					}
					else errorMsg += "Message too short";
				}

//--DELETE USER---------------------------------------------------------------------------------------------------------
				
				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{			
					errorMsg = "Could not delete user; ";

					if(message.getObjContents().size() > 3)
					{						
						String username = (String)message.getObjContents().get(2);

						if(username != null)
						{
							if(isAdmin(reqToken))
							{
								//attempt to delete the group
								if (userExists(username))
								{
									my_gs.deleteUser(username);
									System.out.println(cEngine.formatAsSuccess("User deleted"));
									response.addObject(getGroupKeysForToken(reqToken));

									error = false;
								}
								else errorMsg += "Username not found";	
							}
							else errorMsg += "No membership to specified group";
						}
						else errorMsg += "Check input before trying again";
					}
					else errorMsg += "Message too short";
				}

//--CREATE GROUP---------------------------------------------------------------------------------------------------------
				
				else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
				{
					errorMsg = "Could not create group; ";

					if(message.getObjContents().size() > 3)
					{
						String groupName = (String)message.getObjContents().get(2); //Extract the group name

						//attempt to create the group
						if(groupName != null && createGroup(groupName, reqToken))
						{
							System.out.println(cEngine.formatAsSuccess("Group created"));
							response.addObject(getGroupKeysForToken(reqToken));

							error = false;
						}
						else errorMsg += "Check input before trying again";
					}
					else errorMsg += "Message too short";
				}

//--DELETE GROUP--------------------------------------------------------------------------------------------------------
				
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
					errorMsg = "Could not delete group; ";

					if(message.getObjContents().size() > 3)
					{
						String groupName = (String)message.getObjContents().get(2); //Extract the group name

						//attempt to delete the group
						if(groupName != null && deleteGroup(groupName, reqToken))
						{	
							System.out.println(cEngine.formatAsSuccess("Group deleted"));
							response.addObject(getGroupKeysForToken(reqToken));

							error = false;
						}
						else errorMsg += "Check input before trying again";
					}
					else errorMsg += "Message too short";
				}

//--LIST MEMBERS--------------------------------------------------------------------------------------------------------
				
				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{
					errorMsg = "user list could not be generated; ";

					if(message.getObjContents().size() > 3)
					{
						String groupName = (String)message.getObjContents().get(2); //Extract the group name

						if(groupName != null)
						{
							ArrayList<String> users = listMembers(groupName, reqToken);
							if(users != null && users.size() > 0)
							{
								response.addObject(users);
								System.out.println(cEngine.formatAsSuccess("Member list radded to response"));
								error = false;
							}
							else errorMsg += "No users to list";
						}
						else errorMsg += "Check input before trying again";
					}
					else errorMsg += "Message too short";
				}

//--ADD TO GROUP--------------------------------------------------------------------------------------------------------
				
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
					errorMsg = "Could not add user to group; ";

					if(message.getObjContents().size() > 4)
					{
						String userName = (String)message.getObjContents().get(2); //Extract the user name
						String groupName = (String)message.getObjContents().get(3); //Extract the group name

						if(userName != null && groupName != null)
						{
							//verify group existence
							if(my_gs.groupList.checkGroup(groupName) == true)
							{
								//verify the owner
								if(isGroupOwner(groupName, reqToken))
								{
									//create the group if the it doesn't already exist
									if(addToGroup(userName, groupName, reqToken))
									{
										System.out.println(cEngine.formatAsSuccess("User added to group"));	
										error = false;
									}
								}
								else errorMsg += "No membership to specified group";
							}
							else errorMsg += "No such group exists";
						}
						else errorMsg += "Check input before trying again";
					}		
					else errorMsg += "Message too short";
				}

//--REMOVE FROM GROUP----------------------------------------------------------------------------------------------------
				
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
					errorMsg = "Could not remove user from group; ";

					if(message.getObjContents().size() > 3)
					{
						String userName = (String)message.getObjContents().get(2); //Extract the user name
						String groupName = (String)message.getObjContents().get(3); //Extract the group name

						if(userName != null && groupName != null)
						{
							if(my_gs.groupList.checkGroup(groupName) == true)
							{
								//verify the owner
								if(isGroupOwner(groupName, reqToken))
								{
									//remove user
									if(removeFromGroup(userName, groupName, reqToken))
									{
										System.out.println(cEngine.formatAsSuccess("User removed from group"));
										response.addObject(getGroupKeysForToken(reqToken));
										error = false;
									}
								}
								else errorMsg += "No membership to specified group";
							}
							else errorMsg += "No such group";
						}
						else errorMsg += "Check input before trying again";
					}
					else errorMsg += "Message too short";
				}
				
//--SEE ALL USERS----------------------------------------------------------------------------------------------------
				
				else if(message.getMessage().equals("ALLUSERS")) //Admin wants to see all of the users in existence
				{
					errorMsg = "Could not generate user list; ";

					if(isAdmin(reqToken))//test if they are an admin
					{
						ArrayList<String> usernameList = my_gs.userList.allUsers();
						response.addObject(usernameList);
						System.out.println(cEngine.formatAsSuccess("Full user list added to response"));
						error = false;
					}
					else errorMsg = "No membership to specified group";
				}

//--SEND FINAL MESSAGE---------------------------------------------------------------------------------------------------

				if(error)
				{
					response = genAndPrintErrorEnvelope(errorMsg);
					System.out.println(">> ("+msgNumber+"): Sending error message");
				}
				else 
				{
					System.out.println(">> ("+msgNumber+"): Sending Response: OK");
				}
				response = cEngine.attachHMAC(response, HMACKey);

				cEngine.writeAESEncrypted(response, aesKey, output);
			}
			while(true);	
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}	

//----------------------------------------------------------------------------------------------------------------------
//-- UTILITY FUNCITONS
//----------------------------------------------------------------------------------------------------------------------
	
	//Method to create tokens
	private UserToken createToken(String username, PublicKey key) 
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new token with server's name, user's name, and user's groups
			UserToken yourToken = new UserToken(my_gs.name, username, my_gs.userList.getUserGroups(username), key);

			//sign the token
			yourToken.sign(my_gs.signKeys.getPrivate(), cEngine);
			
			return yourToken;
		}
		else
		{
			return null;
		}
	}
	
	//Method to setup the connection
	protected boolean setUpConnection()
	{
		if(!super.setUpConnection())
		{
			return false;
		}
		//the AESKey is now set. We need to get the token and deal with the MN
		Envelope message = (Envelope)cEngine.readAESEncrypted(aesKey, input);
		msgNumber++;
		Envelope response = new Envelope("OK");
		System.out.println("\n<< ("+msgNumber+"): Request Received: " + message.getMessage());

		return getTokenHandler( message, response);
	}

	public boolean getTokenHandler(Envelope message, Envelope response)
	{

		//check the number of contents
		if(message.getObjContents().size() < 4)
		{
			cEngine.writeAESEncrypted(genAndPrintErrorEnvelope("Message too short"), aesKey, output);
			return false;//go back and wait for a new message
		}

		Integer reqMsgNumber = (Integer)message.getObjContents().get(0); //Get the username
		String username = (String)message.getObjContents().get(1); //Get the username
		String pwd = (String)message.getObjContents().get(2);//get 
		PublicKey key = (PublicKey)message.getObjContents().get(3);

		//Matt, take Note -HMAC-
		if(!cEngine.checkHMAC(message, HMACKey)) return false;		

        //check message number
		if(msgNumber.intValue() != reqMsgNumber.intValue())
		{
			rejectMessageNumber(response, reqMsgNumber, output);
			return false;
		}
        System.out.println(cEngine.formatAsSuccess("Message number matches"));

		try
		{
			//NOTE: Its bad practice to tell the user what login error occurred
			//they could use it to fish for valid usernames
			if(username == null)
			{
				System.out.println(cEngine.formatAsError("No username"));
				cEngine.writeAESEncrypted(new Envelope("Login failed"), aesKey, output);
				return false;
			}
			else if(!my_gs.userList.checkUser(username))
			{
				System.out.println(cEngine.formatAsError("Username not found: "+username));
				cEngine.writeAESEncrypted(new Envelope("Login failed"), aesKey, output);
				return false;
			}
			else if(pwd == null || pwd.length() == 0)
			{
				System.out.println(cEngine.formatAsError("No password"));
				cEngine.writeAESEncrypted(new Envelope("Login failed"), aesKey, output);
				return false;
			}
			else if(!my_gs.userList.getUserPassword(username).equals(pwd))
			//else if(!my_gs.userList.checkUserPassword(username, cEngine.hashWithSHA(salt+pwd)))
			{
				System.out.println(cEngine.formatAsError("Wrong password: "+pwd));
				cEngine.writeAESEncrypted(new Envelope("Login failed"), aesKey, output);
				return false;
			}
			else
			{
				UserToken yourToken = createToken(username, key); //Create a token
				System.out.println(cEngine.formatAsSuccess("Authentication cleared"));
				
				msgNumber++;
				//Respond to the client. On error, the client will receive a null token
				response.addObject(msgNumber);
				response.addObject(yourToken);
				response.addObject(getGroupKeysForToken(yourToken));
				response = cEngine.attachHMAC(response, HMACKey);
				System.out.println(">> ("+msgNumber+"): Sending Reponse: OK");
				cEngine.writeAESEncrypted(response, aesKey, output);

				System.out.println(cEngine.formatAsSuccess("Token sent"));
				return true;
			}
		}
		catch(Exception e)
		{
			System.out.println(cEngine.formatAsError("Exception thrown during token setup"));
			e.printStackTrace();
			return false;
		}
	}

	private HashMap<String, HashMap<Date, AESKeySet>> getGroupKeysForToken(UserToken token)
	{
		HashMap<String, HashMap<Date, AESKeySet>> fullMap = new HashMap<String, HashMap<Date, AESKeySet>>();
		List<String> groupList = token.getGroups();

		//add all of the keys that a user has priveledges for
		for(int i = 0; i < groupList.size(); i++)
		{
			fullMap.put(groupList.get(i), groupFileKeyMap.getKeyMapForGroup(groupList.get(i), false));
		}
		return fullMap;
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
	private boolean createUser(String username, String pwd, UserToken yourToken) throws NoSuchAlgorithmException
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
					// Matt ~ 2013 2 April
					// my_gs.userList.addUser(username, pwd);
					my_gs.userList.addUser(username, cEngine.hashWithSHA(salt+pwd));
					System.out.print("User added: "+userExists(username));
					my_gs.addUserToGroup("global", username); // add all users to global by default
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
	
	private boolean createGroup(String groupName, UserToken yourToken)
	{
		//Check if group exists
		if(!groupExists(groupName))
		{
			my_gs.createGroup(groupName, yourToken.getSubject());
			return true;
		}
		return false; //requester does not exist
	}

	private boolean deleteGroup(String groupName, UserToken yourToken)
	{
		//verify that the group exists, and that the user is an owner
		if(groupExists(groupName) && isGroupOwner(groupName, yourToken))
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
		if(groupExists(groupName) && isGroupOwner(groupName, yourToken))
		{
			members = my_gs.groupList.getGroupMembers(groupName);
		}
		return members;
	}

	private boolean addToGroup(String userName, String groupName, UserToken yourToken)
	{
		//verify that the group exists, that the user is an owner, and that the user isnt already a member
		if(userExists(userName) && groupExists(groupName) && isGroupOwner(groupName, yourToken) && !my_gs.groupList.getGroupMembers(groupName).contains(userName))
		{
			my_gs.addUserToGroup(groupName, userName);
			return true;
		}
		return false;
	}

	private boolean removeFromGroup(String userName, String groupName, UserToken yourToken)
	{
		//verify that the group exists, and that the user is an owner
		if(groupExists(groupName) && isGroupOwner(groupName, yourToken) && userExists(userName))
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

//----------------------------------------------------------------------------------------------------------------------
//-- READABILITY WRAPPERS
//----------------------------------------------------------------------------------------------------------------------
	
	//wrappers to cleanup code
	private boolean userExists(String userName)
	{
		return my_gs.userList.allUsers().contains(userName);
	}
	private boolean groupExists(String group)
	{
		return my_gs.groupList.checkGroup(group);
	}
	private boolean userInGroup(String userName, String group)
	{
		return my_gs.groupList.checkGroup(group);
	}
	private boolean isGroupOwner(String group, UserToken token)
	{
		return my_gs.groupList.getGroupOwners(group).contains(token.getSubject());
	}
	
}
