/* This list represents the users on the server */
import java.util.*;

public class UserList implements java.io.Serializable 
{
	private Hashtable<String, User> list = new Hashtable<String, User>();
	private static final long serialVersionUID = 7600343803563417992L;
   
	
	public synchronized void addUser(String username, String pwd)
	{
		User newUser = new User(pwd);
		list.put(username, newUser);
	}
		
	public synchronized void deleteUser(String username)
	{
		if(list.get(username) == null) return;
		list.remove(username);
	}
		
	//This checks if user: username exists
	public synchronized boolean checkUser(String username)
	{
		if(list.containsKey(username))
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	
	// Matt ~ 2013 1 April
	public synchronized Boolean checkUserPassword(String username, String pwd)
	{
		return (list.get(username).password().equals(pwd));
	}
	
	public synchronized String getUserPassword(String username)
	{
		return list.get(username).password();
	}
	
	public synchronized ArrayList<String> allUsers()
	{
		Enumeration keys = list.keys();
		ArrayList<String> usernames = new ArrayList<String>();
		while(keys.hasMoreElements())
		{
			usernames.add((String)keys.nextElement());
		}
		
		return usernames;
	}
	
	//These are all calls to the User subclass
	public synchronized ArrayList<String> getUserGroups(String username)
	{
		return list.get(username).getGroups();
	}
	
	public synchronized ArrayList<String> getUserOwnership(String username)
	{
		return list.get(username).getOwnership();
	}
	
	public synchronized void addGroup(String user, String groupname)
	{
		list.get(user).addGroup(groupname);
	}
	
	public synchronized void removeGroup(String user, String groupname)
	{
		list.get(user).removeGroup(groupname);
	}
	
	public synchronized void addOwnership(String user, String groupname)
	{
		list.get(user).addOwnership(groupname);
	}
	
	public synchronized void removeOwnership(String user, String groupname)
	{
		list.get(user).removeOwnership(groupname);
	}

class User implements java.io.Serializable 
{
	private static final long serialVersionUID = -6699986336399821598L;
	private ArrayList<String> groups;
	private ArrayList<String> ownership;
	private String password;
	
	public User(String pwd)
	{
		groups = new ArrayList<String>();
		ownership = new ArrayList<String>();
		password = pwd;
	}
	
	public String password()
	{
		return password;
	}
	
	public ArrayList<String> getGroups()
	{
		return groups;
	}
	
	public ArrayList<String> getOwnership()
	{
		return ownership;
	}
	
	public void addGroup(String group)
	{
		groups.add(group);
	}
	
	public void removeGroup(String group)
	{
		if(!groups.isEmpty())
		{
			if(groups.contains(group))
			{
				groups.remove(groups.indexOf(group));
			}
		}
	}
	
	public void addOwnership(String group)
	{
		ownership.add(group);
	}
	
	public void removeOwnership(String group)
	{
		if(!ownership.isEmpty())
		{
			if(ownership.contains(group))
			{
				ownership.remove(ownership.indexOf(group));
			}
		}
	}
}
}
