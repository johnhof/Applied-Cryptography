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

import java.util.*;

public class UserToken implements UserTokenInterface, java.io.Serializable
{
	private String issuer; 
	private String subject; 
    private List<String> groups;
    private byte[] signature;
	private PublicKey publicKey;
	private Integer msgNumber;
	private byte[] msgNumberSignature;

	public UserToken(String Issuer, String Subject, PublicKey key)
	{
		issuer = Issuer; 
		subject = Subject; 
        groups = null;
        signature = null;
		publicKey = key;
		msgNumber = new Integer((new SecureRandom()).nextInt());
		msgNumberSignature = null;
	}

    public UserToken(String Issuer, String Subject, List<String> Groups, PublicKey key)
    {
        issuer = Issuer; 
        subject = Subject; 
        groups = Groups;
        signature = null;
		publicKey = key;
		msgNumber = new Integer((new SecureRandom()).nextInt());
		msgNumberSignature = null;
    }

    public String getIssuer()
    {
    	return issuer; 
    }

    public String getSubject()
    {
    	return subject;
    }

    public List<String> getGroups()
    {
        return groups; 
    }

    public Boolean addGroup(String group)
    {
        return groups.add(group);
    }

    public Boolean inGroup(String group)
    {
        return groups.contains(group);
    }

    public Boolean removeGroup(String group)
    {
        return groups.remove(group);
    }

    public int groupCount()
    {
        return groups.size();
    }

    public void clearGroups()
    {
        groups.clear();
    }
	
	public Key getKey()
	{
		return publicKey;
	}
	
	public int getMsgNumber()
	{
		return msgNumber.intValue();
	}
	
	public void setMsgNumber(int replacementMsgNumber)
	{
		msgNumber = new Integer(replacementMsgNumber);
	}

//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-- SIGNING AND VERIFICATION 
//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    public void sign(PrivateKey key, CryptoEngine cEngine)
    {
        signature = cEngine.RSASign(getContentsInBytes(cEngine), key);
    }

	public void signMsgNumber(PrivateKey key, CryptoEngine cEngine)
	{
		msgNumberSignature = cEngine.RSASign(cEngine.serialize(msgNumber), key);
	}
	
	public boolean verifyMsgNumberSignature(CryptoEngine cEngine)
	{
		return cEngine.RSAVerify(cEngine.serialize(msgNumber), msgNumberSignature, publicKey);
	}

    public boolean verifySignature(PublicKey key, CryptoEngine cEngine)
    {
        return cEngine.RSAVerify(getContentsInBytes(cEngine),  signature, key);
    }

//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-- Utility Functions
//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    //megre the token contents into an array
    private byte[] getContentsInBytes(CryptoEngine cEngine)
    {
        ArrayList<Object> contents = new ArrayList<Object>();
        contents.add(issuer);
        contents.add(subject);
		contents.add(publicKey);
        if(groups != null)contents.add(groups);
        return cEngine.serialize(contents);
    }
}
