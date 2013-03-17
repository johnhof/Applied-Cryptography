/* superclass used to share functions between  file and group servers*/

import java.lang.Thread;
import java.net.Socket;
import java.util.List;
import java.util.ArrayList;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.util.*;

//These threads are spun off by FileServer.java
public class ServerThread extends Thread
{
	protected final Socket socket;
	protected CryptoEngine cEngine;
	protected AESKeySet aesKey;

	public ServerThread(Socket _socket)
	{
		socket = _socket;
		cEngine = new CryptoEngine();
		aesKey = null;
	}

	protected Envelope genAndPrintErrorEnvelope(String error)
	{
		if(cEngine == null)	cEngine = new CryptoEngine();

		System.out.println(cEngine.formatAsError(error));
		return new Envelope(error);
	}
}