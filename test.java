
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

import java.util.List;

import java.io.*;

public class test
{
    public static void main (String[] args)
    {
        String resourceFile = "GroupResources.bin";
        String keyDisrtoFile = "GroupPublicKey.bin";
        ObjectOutputStream outStream;
        InputStreamReader reader = new InputStreamReader(System.in);
        BufferedReader in = new BufferedReader(reader);
        ObjectInputStream resourceStream;
        ObjectInputStream pKeyStream;

    	CryptoEngine cEngine = new CryptoEngine();

        KeyPair keys = null;
        PublicKey pk = null;

        try
        {
            FileInputStream fis = new FileInputStream(resourceFile);
            resourceStream = new ObjectInputStream(fis);

            //retrieve the keys used for signing
            keys = (KeyPair)resourceStream.readObject();
        }
        catch(Exception e)
        {
            System.out.println("ERROR:  GROUPSERVER;  could not load resource file");
            System.exit(-1);
        }


        try
        {
            FileInputStream fis = new FileInputStream(keyDisrtoFile);
            pKeyStream = new ObjectInputStream(fis);

            //retrieve the keys used for signing
            pk = (PublicKey)pKeyStream.readObject();
        }
        catch(Exception e)
        {
            System.out.println("ERROR:  GROUPSERVER;  could not load resource file");
            System.exit(-1);
        }

    	UserToken token = new UserToken("issuer", "Subject");

        token.sign(keys.getPrivate());

    	System.out.println("\nvalid signature from set: " + token.verifySignature(keys.getPublic()));

        System.out.println("\nvalid signature: " + token.verifySignature(pk));
    }

}