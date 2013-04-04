
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
        
        GroupKeyMapController mapController = GroupKeyMapController.getInstance("t","t");

        Date tempDate = new Date();


        tempDate.setDate(80);
        mapController.addNewGroup("j", tempDate, cEngine.genAESKeySet(), false);

        tempDate.setDate(200);
        mapController.addNewGroup("d", tempDate, cEngine.genAESKeySet(), false);tempDate = new Date();
        tempDate.setDate(260);
        mapController.addToGroup("d", tempDate, cEngine.genAESKeySet(), false);tempDate = new Date();
        tempDate.setDate(300);
        mapController.addToGroup("d", tempDate, cEngine.genAESKeySet(), false);tempDate = new Date();

        tempDate.setDate(500);
        mapController.addNewGroup("e", tempDate, cEngine.genAESKeySet(), false);tempDate = new Date();
        tempDate.setDate(600);
        mapController.addToGroup("e", tempDate, cEngine.genAESKeySet(), false);tempDate = new Date();

        System.out.println("\n------ MAP CONTROLLER 1 ------");
        //mapController.syncWithNewKeyMap(map1);
        System.out.println(mapController.toString());

        mapController.getLatestKey("d", false);
    }
}