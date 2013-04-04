/* Group server. Server loads the users from UserList.rsc.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file. 
 */

/*
 * TODO: This file will need to be modified to save state related to
 *       groups that are created in the system
 *
 */
 
 //It seems that all that needs done is a group list save process similar to the userlist


import java.nio.charset.Charset;
import java.security.*;
import javax.crypto.*;
import java.net.*;
import java.io.*;
import java.util.*;

//import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GroupServer extends Server 
{

	//IMPORTANT: server listens on port 6666
	public static final int SERVER_PORT = 6666;
	public KeyPair signKeys;
	public UserList userList;
	public String userFile;
	public GroupList groupList;
	public String groupFile;
	//^^^^This should really be a database...
	protected GroupKeyMapController groupFileKeyMap;
    
	public GroupServer() 
	{
		//pass in the server type to create the appropriate directory
		super(SERVER_PORT, "ALPHA", "Group");
		userFile = resourceFolder+"UserList.rsc";
		groupFile = resourceFolder+"GroupList.rsc";
	}
	
	public GroupServer(int _port) 
	{
		//pass in the server type to create the appropriate directory
		super(_port, "ALPHA", "Group");
		userFile = resourceFolder+"UserList.rsc";
		groupFile = resourceFolder+"GroupList.rsc";
	}
	
	public void start() 
	{
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;
		ObjectInputStream resourceStream;
		String sigKeyFile = resourceFolder+"SigKeys.rsc";

		//open the resource folder, remove it if it had to be generated
		File file = new File(resourceFolder);
		if(file.mkdir())
		{
            file.delete();
			System.out.println("\nResourceGenerator must be run before continuing\n");
			return;
		}

		System.out.println("\nSetting up resources");


		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));
		
		//set up the authentication key
		if(!setAuthKey()) System.exit(-1);

//--SET UP KEYMAP-------------------------------------------------------------------------------------------------------

		//grab/create the shared instance of our keymap
		groupFileKeyMap = GroupKeyMapController.getInstance(name, resourceFolder);

//--RETRIEVE THE SIGNING KEY--------------------------------------------------------------------------------------------
		try
		{
			FileInputStream fis = new FileInputStream(sigKeyFile);
			resourceStream = new ObjectInputStream(fis);

			//retrieve the keys used for signing
			signKeys = (KeyPair)resourceStream.readObject();
		}
		catch(Exception e)
		{
			System.out.println("GROUPSERVER \nERROR: could not load key file");
			System.exit(-1);
		}

//--SET UP THE GROUP LIST-----------------------------------------------------------------------------------------------
		try
		{
			System.out.println("\nTrying to access GroupList File");
			FileInputStream fis = new FileInputStream(groupFile);
			groupStream = new ObjectInputStream(fis);
			groupList = (GroupList)groupStream.readObject();
			System.out.println(cEngine.formatAsSuccess("GroupList recovered"));		
		}
		catch(FileNotFoundException e)
		{
			System.out.println(cEngine.formatAsSuccess("GroupList does not exist. Creating GroupList"));
			System.out.println(cEngine.formatAsSuccess("No groups currently exists"));

			groupList = new GroupList();
		}
		catch(IOException e)
		{
			System.out.println("Error reading from groupList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from groupList file");
			System.exit(-1);
		}

//--SET UP THE USER LIST------------------------------------------------------------------------------------------------

		//Open user file to get user list
		try
		{
			System.out.println("\nTrying to access UserList File");
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList)userStream.readObject();
			System.out.println(cEngine.formatAsSuccess("UserList recovered"));		
		}
		catch(FileNotFoundException e)
		{
			System.out.println(cEngine.formatAsSuccess("No users currently exist. Your account will be the administrator"));
			System.out.println(cEngine.formatAsSuccess("UserList File Does Not Exist. Creating UserList"));
			
			String username = null;
			String password = null;
			String passwordTemp = null;

			//prompt the admin for a name and a verified password
			do
			{
				System.out.print("Enter your username: ");
				username = console.next();
				System.out.print("Enter your password: ");
				password = console.next();
				System.out.print("Verify password: ");
				passwordTemp = console.next();

				if(password.equals(passwordTemp)) break;
				System.out.println("Passwords don't match");
			}
			while(true);
			
			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			userList = new UserList();
			userList.addUser(username, password);
			createGroup("ADMIN", username);
			createGroup("global", username); //all users are added to the global group
			System.out.println(cEngine.formatAsSuccess("Default groups created: ADMIN, global"));
		}
		catch(IOException e)
		{
			System.out.println(cEngine.formatAsError("Error reading from UserList file"));
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println(cEngine.formatAsError("Error reading from UserList file"));
			System.exit(-1);
		}

//--INTEGRITY CHECK-----------------------------------------------------------------------------------------------------

		//check for null values just in case
		if(userList == null)
		{
			System.out.println(cEngine.formatAsError("File reading error, userlist could not be recovered"));
			System.exit(-1);
		}
		if(groupList == null)
		{
			System.out.println(cEngine.formatAsError("File reading error, grouplist could not be recovered"));
			System.exit(-1);
		}


//--SET UP SAVE DEMON---------------------------------------------------------------------------------------------------

		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();
		
		System.out.println("\nUPDATE: GroupServer; setup succesful");
		
//--SET UP SOCKET LOOP--------------------------------------------------------------------------------------------------

		//This block listens for connections and creates threads on new connections
		try
		{
			
			final ServerSocket serverSock = new ServerSocket(port);
			
			Socket sock = null;
			GroupThread thread = null;
			
			//spawn a thread to handle each socket
			while(true)
			{
				sock = serverSock.accept();
				//THREAD HANDLES CORE FUNCTIONALITY. SEE GroupThread.java				
				thread = new GroupThread(sock, this);
				thread.start();
			}
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}


//----------------------------------------------------------------------------------------------------------------------
//-- UTILITY FUNCITONS
//-- !!!!!ALWAYS USE THESE TO ADD AND REMOVE GROUPS AND USERS. THESE LISTS MUST BE SYNCHRONIZED!!!!!
//-- also note that these assume data integrity is pure. do checks before calling them
//----------------------------------------------------------------------------------------------------------------------

	//does not check if group exists
	public void createGroup(String groupName, String creator)
	{
		userList.addGroup(creator, groupName);
		userList.addOwnership(creator, groupName);

		groupList.addGroup(groupName);
		groupList.addMember(groupName, creator);
		groupList.addOwner(groupName, creator);

		//generate the groups file key 
		//no need to make this thread safe, there should only ever be one instance of groupserver
       	groupFileKeyMap.addNewGroup(groupName, new Date(), cEngine.genAESKeySet(), true);
		System.out.println(cEngine.formatAsSuccess("New group key generated"));       	
	}

	//does not check if group exists
	public void deleteGroup(String groupName)
	{
		//remove ownership for each owner in the group
		ArrayList<String> owners = groupList.getGroupOwners(groupName);
		for(String owner : owners)
		{
			userList.removeOwnership(owner, groupName);
		}

		//remove membership for each user in the group
		ArrayList<String> members = groupList.getGroupMembers(groupName);
		for(String member : members)
		{
			userList.removeGroup(member, groupName);
		}

		groupList.deleteGroup(groupName);
		
		//delete the group keys
		//no need to make this thread safe, there should only ever be one instance of groupserver
       	groupFileKeyMap.deleteGroup(groupName, new Date(), cEngine.genAESKeySet(), false);
		System.out.println(cEngine.formatAsSuccess("Group keys deleted"));       	
	}

	//does not check if the group or user exists
	public void addUserToGroup(String groupName, String user)
	{
		userList.addGroup(user, groupName);
		groupList.addMember(groupName, user);
	}

	//does not check if group or user exists, or if user is in group, or if user is the owner
	public void removeUserFromGroup(String groupName, String user)
	{
		userList.removeGroup(user, groupName);
		groupList.removeMember(groupName, user);

		//generate the groups file key 
		//no need to make this thread safe, there should only ever be one instance of groupserver
       	groupFileKeyMap.addNewKeytoGroup(groupName, new Date(), cEngine.genAESKeySet(), false);
		System.out.println(cEngine.formatAsSuccess("New group key generated"));       	
	}

	//does not check if group or user exists, or if user is in group, or if user is the owner
	public void removeOwnerFromGroup(String groupName, String owner)
	{
		userList.removeOwnership(owner, groupName);
		groupList.removeOwner(groupName, owner);	
	}
	
	//does not check if group or user exists, or if user is in group, or if user is the owner
	public void addOwnerToGroup(String groupName, String owner)
	{
		userList.addOwnership(owner, groupName);
		groupList.addOwner(groupName, owner);
	}

	public void deleteUser(String user)
	{
		//remove ownership for each owner in the group
		ArrayList<String> ownedGroups = userList.getUserOwnership(user);
		for(String ownedGroup : ownedGroups)
		{
			groupList.removeOwner(ownedGroup, user);
		}

		//remove membership for each user in the group
		ArrayList<String> groups = userList.getUserGroups(user);
		for(String group : groups)
		{
			groupList.removeMember(group, user);
		}

		userList.deleteUser(user);
	}

	private boolean userInGroup(String userName, String group)
	{
		//return false if the user or group doesnt exist, 
		//or the group donet contain the user, or the user have the group membership
		if(!groupList.checkGroup(group) || !userList.checkUser(userName) || 
			!groupList.getGroupMembers(group).contains(userName) || 
			!userList.getUserGroups(userName).contains(group)) return false;
		return true;
	}
}

//----------------------------------------------------------------------------------------------------------------------
//-- SAVING DEMONS
//----------------------------------------------------------------------------------------------------------------------

//This thread saves the user list
class ShutDownListener extends Thread
{
	public GroupServer my_gs;
	
	public ShutDownListener (GroupServer _gs) {
		my_gs = _gs;
	}
	
	public void run()
	{
		//write userlist to directory
		System.out.println("\nShutting down server...");
		ObjectOutputStream outStream;
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream(my_gs.getResourceFolder()+"UserList.rsc"));//save UserList
			outStream.writeObject(my_gs.userList);

			outStream = new ObjectOutputStream(new FileOutputStream(my_gs.getResourceFolder()+"GroupList.rsc"));//save GroupList
			outStream.writeObject(my_gs.groupList);

		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSave extends Thread
{
	public GroupServer my_gs;
	
	public AutoSave (GroupServer _gs) {
		my_gs = _gs;
	}
	
	public void run()
	{
		//write user list to directory every 5 minutes
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("\nAutosave group and user lists...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream(my_gs.getResourceFolder()+"UserList.rsc"));//save UserList
					outStream.writeObject(my_gs.userList);

					outStream = new ObjectOutputStream(new FileOutputStream(my_gs.getResourceFolder()+"GroupList.rsc"));//save GroupList
					outStream.writeObject(my_gs.groupList);
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
			}
			catch(Exception e)
			{
				System.out.println("\nAutosave Interrupted");
			}
		}while(true);
	}
}
