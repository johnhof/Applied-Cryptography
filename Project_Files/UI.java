import java.net.Socket;
import java.io.*;
import java.util.*;

public class UI
{
	public static void main(String[] args)
	{
		//GroupServer is named "ALPHA" and is on 8766
		//FileServer is named "FilePile" and is on 4321

		System.out.println("Attempting to connect to GroupServer.\n");
		GroupClient gUser = new GroupClient();
		gUser.connect(null, 8766);
		FileClient fUser = new FileClient();
		fUser.connect(null, 4321);
		//UI is connecting to localhost. May change with cmd line options later
		
		
		System.out.println("Please enter a username.");
		Scanner in = new Scanner(System.in);

		String username = in.nextLine();
		UserToken token = gUser.getToken(username);
		//confirmed that this token is correct
		System.out.println("What would you like to do now?");//Queries the user
		
	}
}
