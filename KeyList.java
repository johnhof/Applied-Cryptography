import java.util.*;
import java.security.*;
import javax.crypto.*;

public class KeyList implements java.io.Serializable
{
	private Hashtable<String, Key> list = new Hashtable<String, Key>();
	
	public synchronized void addKey(String server, Key key)
	{
		list.put(server, key);
	}
	
	public synchronized void deleteKey(String server)
	{
		list.remove(server);
	}
	
	public synchronized boolean checkServer(String server)
	{
		if(list.containsKey(server))
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	
	public synchronized Key getKey(String server)
	{
		return list.get(server);
	}
}