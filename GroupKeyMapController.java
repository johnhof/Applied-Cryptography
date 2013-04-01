import java.net.*;
import java.security.*;
import javax.crypto.*;
import java.io.*;
import java.util.*;
import javax.crypto.spec.IvParameterSpec;

/*
	CLASS DESCRIPTION: (Singleton)
	this class should be used to load/save/update the key map. Its primary purpose 
	is to share the keys resources between instances of the client, while maintaining an
	easily updateable, synchronous state between concurrent clients of a single user.
*/

public class GroupKeyMapController
{
	//group file key maps: HashMap<groupName, HashMap<keyID, AESKeySet>>
	private HashMap<String, HashMap<Integer, AESKeySet>> groupFileKeyMap;
	private String resourceFile;
	private HashMap<String, Integer> newestKeyIDs;
	private static GroupKeyMapController instance = null;
	private boolean initialized = false;
	private CryptoEngine cEngine;

//--SINGLETON METHODS---------------------------------------------------------------------------------------------------
	private GroupKeyMapController(){}

	public synchronized static GroupKeyMapController getInstance()
	{
		//only generate a new instance if one doesnt already exist
		if(instance == null)instance = new GroupKeyMapController();

		return instance;
	}

//--INITIALIZATION FUNTIONS---------------------------------------------------------------------------------------------

	public boolean setUpController(String userName, String userFolder)
	{
		cEngine = new CryptoEngine();
		groupFileKeyMap = new HashMap<String, HashMap<Integer, AESKeySet>>();
		resourceFile = userFolder+"/"+userName+"_group_file_keys.rsc";
		newestKeyIDs = new HashMap<String, Integer>();

		loadKeyMap();
		return true;
	}

//--IO METHODS----------------------------------------------------------------------------------------------------------
	public boolean loadKeyMap()
	{
		try
		{
			//Read in the key
			FileInputStream fis = new FileInputStream(resourceFile);
			ObjectInputStream keyStream = new ObjectInputStream(fis);
			groupFileKeyMap = (HashMap<String, HashMap<Integer, AESKeySet>>)keyStream.readObject();
			System.out.println(cEngine.formatAsSuccess("group/file key map recovered"));
		}
		catch(FileNotFoundException exc)
		{
			System.out.println(cEngine.formatAsSuccess("group/file key map does not exist. Creating it"));
			groupFileKeyMap = new HashMap<String, HashMap<Integer, AESKeySet>>();
			saveKeyMap();
		}
		catch(Exception exc)
		{
			System.out.println(cEngine.formatAsError("This shit' fucked up"));
		}
		return true;
	}

	public boolean saveKeyMap()
	{
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
			return true;
	}

//--RETRIEVAL METHODS---------------------------------------------------------------------------------------------------

	public HashMap<Integer, AESKeySet> getKeyMapForGroup(String groupName)
	{
		if (groupFileKeyMap.containsKey(groupName))return groupFileKeyMap.get(groupName);
		return null;
	}
	public AESKeySet getKeyFromNameAndID(String groupName, Integer keyID)
	{
		HashMap<Integer, AESKeySet> map = getKeyMapForGroup(groupName);		
		if(map != null && map.containsKey(keyID)) return map.get(keyID);
		return null;
	}

//--MANIPULATION METHODS------------------------------------------------------------------------------------------------

	public boolean addNewKeytoGroup(String groupName, Integer keyID, AESKeySet keySet)
	{
		HashMap<Integer, AESKeySet> map = getKeyMapForGroup(groupName);
		if(map == null || map.containsKey(keyID)) return false;
		map.put(keyID, keySet);
		return true;
	}



}