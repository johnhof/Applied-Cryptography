/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file. 
 */

/*
 * TODO: This file will need to be modified to save state related to
 *       groups that are created in the system
 *
 */
 
 //It seems that all that needs done is a group list save process similar to the userlist

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.PublicKey;
import java.security.PrivateKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

//import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;

/*ADDED ELEMENTS:
-groupList: string to easily check group existence
-groupExists: return true if the group exists

NOTE: this is probably not the right way to do this, but I'm at a loss for alternatives
*/

public class GroupServer extends Server {

	public static final int SERVER_PORT = 8766;

	public KeyPair signKeys;
	public UserList userList;
	public GroupList groupList;
	//^^^^This should really be a database...

	public CryptoEngine cEngine;
    
	public GroupServer() 
	{
		super(SERVER_PORT, "ALPHA");
    	cEngine = new CryptoEngine();
	}
	
	public GroupServer(int _port) 
	{
		super(_port, "ALPHA");
    	cEngine = new CryptoEngine();
	}
	
	public void start() 
	{
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created
		
		String resourceFile = "GroupResources.bin";
		String userFile = "UserList.bin";
		String groupFile = "GroupList.bin";
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;
		ObjectInputStream resourceStream;

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));

//----------------------------------------------------------------------------------------------------------------------
//--ADDED: resource setup
//----------------------------------------------------------------------------------------------------------------------
		try
		{
			FileInputStream fis = new FileInputStream(resourceFile);
			resourceStream = new ObjectInputStream(fis);

			//retrieve the keys used for signing
			signKeys = (KeyPair)resourceStream.readObject();
		}
		catch(Exception e)
		{
			System.out.println("ERROR:  GROUPSERVER;  could not load resource file");
			System.exit(-1);
		}
//----------------------------------------------------------------------------------------------------------------------

//----------------------------------------------------------------------------------------------------------------------
//--ADDED: groupList setup
//----------------------------------------------------------------------------------------------------------------------
		try
		{
			FileInputStream fis = new FileInputStream(groupFile);
			groupStream = new ObjectInputStream(fis);
			groupList = (GroupList)groupStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("groupList File Does Not Exist. Creating resources...");
			System.out.println("No groupList currently exists");

			groupList = new GroupList();
		}
		catch(IOException e)
		{
			System.out.println("Error reading from resource file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from resouce file");
			System.exit(-1);
		}

//----------------------------------------------------------------------------------------------------------------------


		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList)userStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			String username = console.next();
			
			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			userList = new UserList();
			userList.addUser(username);
			createGroup("ADMIN", username);
		}
		catch(IOException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}

		//check for null values just in case
		if(userList == null || groupList == null)
		{
			System.out.println("File reading error, data could not be recovered");
			System.exit(-1);
		}

		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();
		
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

		System.out.println("\nUPDATE: GroupServer; setup succesful");

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
//----------------------------------------------------------------------------------------------------------------------
}

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
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);

//----------------------------------------------------------------------------------------------------------------------
//-- ADDED: groupList storage
//----------------------------------------------------------------------------------------------------------------------
			outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
			outStream.writeObject(my_gs.groupList);
//----------------------------------------------------------------------------------------------------------------------

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
				System.out.println("Autosave group and user lists...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					outStream.writeObject(my_gs.userList);

//----------------------------------------------------------------------------------------------------------------------
//-- ADDED: groupList storage
//----------------------------------------------------------------------------------------------------------------------
					outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
					outStream.writeObject(my_gs.groupList);
//----------------------------------------------------------------------------------------------------------------------
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		}while(true);
	}
}
