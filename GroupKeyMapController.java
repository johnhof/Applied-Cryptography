import java.net.*;
import java.security.*;
import javax.crypto.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import javax.crypto.spec.IvParameterSpec;

/*
	CLASS DESCRIPTION: (Singleton)
	this class should be used to load/save/update the key map. Its primary purpose 
	is to share the keys resources between instances of the client, while maintaining an
	easily updateable, synchronous state between concurrent clients of a single user.
*/

public class GroupKeyMapController implements java.io.Serializable
{
	//group file key maps: HashMap<groupName, HashMap<keyID, AESKeySet>>
	private HashMap<String, HashMap<Date, AESKeySet>> groupFileKeyMap;
	private String resourceFile;
	private HashMap<String, Date> newestKeyIDs;

	private  static GroupKeyMapController instance = null;
	private  static CryptoEngine cEngine;

	private  Lock lock;

//--SINGLETON METHODS---------------------------------------------------------------------------------------------------
	private GroupKeyMapController(){}

	//creates an instance using the username and folder to generate resources
	public static synchronized GroupKeyMapController getInstance(String userName, String userFolder)
	{
		//only generate a new instance if one doesnt already exist
		if(instance == null)
		{
			instance = new GroupKeyMapController();
			instance.setUpController(userName, userFolder);
		}
		else
		{
			System.out.println(cEngine.formatAsSuccess("group/file key map shared"));			
		}

		return instance;
	}

//--INITIALIZATION FUNTIONS---------------------------------------------------------------------------------------------

	public synchronized boolean setUpController(String userName, String userFolder)
	{
		lock = new ReentrantLock();
		cEngine = new CryptoEngine();
		groupFileKeyMap = new HashMap<String, HashMap<Date, AESKeySet>>();
		resourceFile = userFolder+"/"+userName+"_group_file_keys.rsc";
		newestKeyIDs = new HashMap<String, Date>();

		loadKeyMap();
		return true;
	}

//--IO METHODS----------------------------------------------------------------------------------------------------------
	public synchronized boolean loadKeyMap()
	{
		lock.lock();

		try
		{
			//Read in the key
			FileInputStream fis = new FileInputStream(resourceFile);
			ObjectInputStream keyStream = new ObjectInputStream(fis);
			groupFileKeyMap = (HashMap<String, HashMap<Date, AESKeySet>>)keyStream.readObject();
			System.out.println(cEngine.formatAsSuccess("group/file key map file recovered"));
		}
		catch(FileNotFoundException exc)
		{
			System.out.println(cEngine.formatAsSuccess("group/file key map does not exist. Creating it"));
			groupFileKeyMap = new HashMap<String, HashMap<Date, AESKeySet>>();
			saveKeyMap();
		}
		catch(Exception exc)
		{
			System.out.println(cEngine.formatAsError("This shit' fucked up"));
		}

		lock.unlock();
		return true;
	}

	public synchronized boolean saveKeyMap()
	{
		lock.lock();

		try
		{
			ObjectOutputStream outStream = new ObjectOutputStream(new FileOutputStream(resourceFile));
			outStream.writeObject(groupFileKeyMap);
			outStream.close();
		}
		catch(Exception e)
		{
			System.out.println(cEngine.formatAsError("This shit' fucked up yo"));
		}

		lock.unlock();
		return true;
	}

//--RETRIEVAL METHODS---------------------------------------------------------------------------------------------------

	public synchronized HashMap<Date, AESKeySet> getKeyMapForGroup(String groupName)
	{
		lock.lock();

		HashMap<Date, AESKeySet> keyMap = null;
		if (groupFileKeyMap.containsKey(groupName)) keyMap = groupFileKeyMap.get(groupName);

		lock.unlock();
		return keyMap;
	}
	public synchronized AESKeySet getKeyFromNameAndDate(String groupName, Date timeIssued)
	{
		lock.lock();

		HashMap<Date, AESKeySet> map = getKeyMapForGroup(groupName);		
		AESKeySet keySet = null;
		if(map != null && map.containsKey(timeIssued)) keySet = map.get(timeIssued);

		lock.unlock();
		return keySet;
	}

//--MANIPULATION METHODS------------------------------------------------------------------------------------------------

	public synchronized boolean addNewKeytoGroup(String groupName, Date timeIssued, AESKeySet keySet)
	{
		lock.lock();

		HashMap<Date, AESKeySet> map = getKeyMapForGroup(groupName);
		if(map == null || map.containsKey(timeIssued)) 
		{
			lock.unlock();
			return false;
		}
		map.put(timeIssued, keySet);

		lock.unlock();
		return true;
	}

	public synchronized boolean syncWithNewKeyMap()
	{
		return true;
	}
}