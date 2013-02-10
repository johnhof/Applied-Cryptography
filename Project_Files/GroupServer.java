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

	public static final int SERVER_PORT = 8765;
	public UserList userList;
	public ArrayList<String> groupList;

    
	public GroupServer() 
	{
		super(SERVER_PORT, "ALPHA");
	}
	
	public GroupServer(int _port) 
	{
		super(_port, "ALPHA");
	}
	
	public void start() 
	{
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created
		
		String userFile = "UserList.bin";
		String groupFile = "GroupList.bin";
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));

//----------------------------------------------------------------------------------------------------------------------
//--ADDED: groupList setup
//----------------------------------------------------------------------------------------------------------------------
		try
		{
			FileInputStream fis = new FileInputStream(groupFile);
			groupStream = new ObjectInputStream(fis);
			groupList = (ArrayList<String>)groupStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("groupList File Does Not Exist. Creating groupList...");
			System.out.println("No groups currently exist");

			groupList = new ArrayList<String>();
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
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");
			groupList.add("ADMIN");
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

	}
	
//----------------------------------------------------------------------------------------------------------------------
//--UTILITY FUNCITONS
//----------------------------------------------------------------------------------------------------------------------
	public boolean groupExists(String groupName)
	{
		return groupList.contains(groupName);
	}

	public void addGroup(String groupName)
	{
		groupList.add(groupName);
	}
}

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
