
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import java.io.*;

//import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.util.*;

import java.io.*;

public class test
{
    public static void main (String[] args)
    {
    	CryptoEngine cEngine = new CryptoEngine();

        PublicKey pk = null;
        Envelope message = new Envelope("");
        KeyPair keys = cEngine.genRSAKeyPair();

        //set AES key
        AESKeySet aesKey = cEngine.genAESKeySet();
        Integer challenge = new Integer((new SecureRandom()).nextInt());
        Key privateKey = keys.getPrivate();
        Key publicKey = keys.getPublic();
        
/*        byte [] encryptedKey = cEngine.RSAEncrypt(cEngine.serialize(aesKey.getKey()), publicKey);
        byte [] encryptedChallenge = cEngine.RSAEncrypt(cEngine.serialize(challenge), publicKey);

        message.addObject(encryptedKey);
        message.addObject(aesKey.getIV().getIV());
        message.addObject(encryptedChallenge);

        System.out.println("message encrypted");

        byte[] recoveredKey = (byte[])message.getObjContents().get(0);
        byte[] recoveredChallenge = (byte[])message.getObjContents().get(2);

        if(Arrays.equals(encryptedKey, recoveredKey))System.out.println("key recovery successful");
        if(Arrays.equals(encryptedChallenge, recoveredChallenge))System.out.println("key recovery successful");

        byte [] decryptedKey = cEngine.RSADecrypt(encryptedKey, privateKey);
        Key recovered = (Key)cEngine.deserialize(decryptedKey);
/*
        aesKey = new AESKeySet((Key) cEngine.deserialize(cEngine.RSADecrypt(recoveredKey, privateKey)), (IvParameterSpec)message.getObjContents().get(1));
        Integer challenge2 = (Integer)cEngine.deserialize(cEngine.RSADecrypt(recoveredChallenge, privateKey));
        
        System.out.println("message decrypted");
*/

        byte[] result = new byte [117];
        int byteIndex;
        int chunkSize = 117;
        byte[] bytes = cEngine.serialize(aesKey.getKey());
        int inputSize = bytes.length;

        System.out.println("full stream: "+bytes.toString());
        //en/decrypt in 128 byte chunks
        for(byteIndex = 0; byteIndex <= (inputSize-chunkSize); byteIndex+=chunkSize)
        {
            System.out.println("\nloop: "+Arrays.copyOfRange(bytes, byteIndex, byteIndex+chunkSize).toString());
            //append chunk
            byte[] temp = nextChunk(Arrays.copyOfRange(bytes, byteIndex, byteIndex+chunkSize), result);
            result = temp;
            System.out.println("result: "+result);
        }
        //en/decrypt the last chunk (if it happens to be < chunkSize)
        if(byteIndex!=(inputSize-chunkSize))
        {
            System.out.println("\nleftover:"+(inputSize-byteIndex));
           //append chunk
            byte[] temp = nextChunk(Arrays.copyOfRange(bytes, inputSize-byteIndex, inputSize), result);
            result = temp;
        }
        System.out.println("end stream: "+result.toString());
    }

    private static byte[] nextChunk(byte [] chunk, byte [] cryptedBytes)
    {
        try 
        {
            //append chunk
            byte[] result = new byte [cryptedBytes.length+chunk.length];
            System.arraycopy(cryptedBytes, 0, result, 0, cryptedBytes.length );
            System.arraycopy(chunk, 0, result, cryptedBytes.length, chunk.length);

            return result;
        } 
        catch (Exception e) 
        {
            e.printStackTrace();
        }
        return null;

    }

}