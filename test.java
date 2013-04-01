
import java.net.*;
import java.security.*;
import javax.crypto.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import javax.crypto.spec.IvParameterSpec;

//import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class test
{
    public static void main (String[] args)
    {
    	CryptoEngine cEngine = new CryptoEngine();
        
        GroupKeyMapController mapController = GroupKeyMapController.getinstance("t","t");

        Date tempDate = new Date();


        tempDate.setDate(80);
        mapController.addNewGroup("j", tempDate, cEngine.genAESKeySet());

        tempDate.setDate(200);
        mapController.addNewGroup("d", tempDate, cEngine.genAESKeySet());tempDate = new Date();
        tempDate.setDate(260);
        mapController.addToGroup("d", tempDate, cEngine.genAESKeySet());tempDate = new Date();
        tempDate.setDate(300);
        mapController.addToGroup("d", tempDate, cEngine.genAESKeySet());tempDate = new Date();

        tempDate.setDate(500);
        mapController.addNewGroup("e", tempDate, cEngine.genAESKeySet());tempDate = new Date();
        tempDate.setDate(600);
        mapController.addToGroup("e", tempDate, cEngine.genAESKeySet());tempDate = new Date();

        System.out.println("\n------ MAP CONTROLLER 1 ------");
        //mapController.syncWithNewKeyMap(map1);
        System.out.println(mapController.toString());
/*
        Envelope message = new Envelope("OK");
        message.addObject(map2); 
        AESKeySet key = cEngine.genAESKeySet();
        byte [] encrypted = cEngine.AESEncrypt(cEngine.serialize(message), key);
        System.out.println("ENCRYPTED");
        byte [] decrypted = cEngine.AESDecrypt(encrypted, key);
        System.out.println("DECRYPTED");
        Envelope response = (Envelope)cEngine.deserialize(decrypted);

        map2 = (HashMap<String, HashMap<Date, AESKeySet>>)response.getObjContents().get(0);
*/



        tempDate.setDate(500);
        mapControllerNew.addNewGroup("q", tempDate, cEngine.genAESKeySet());tempDate = new Date();
        tempDate.setDate(600);
        mapControllerNew.addToGroup("q", tempDate, cEngine.genAESKeySet());tempDate = new Date();

        System.out.println("\n------ MAP CONTROLLER 2 ------");
        System.out.println(mapControllerNew.toString());

        System.out.println("\n------ MAP CONTROLLER UPDATED ------");
        mapControllerNew.syncWithNewKeyMap(mapController.getFullMap());
        System.out.println(mapControllerNew.toString()); 
    }

}