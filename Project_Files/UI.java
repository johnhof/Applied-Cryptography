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
		GroupClient user = new GroupClient();
		user.connect(null, 8766);
		
		System.out.println("Please enter a username.");
		Scanner in = new Scanner(System.in);

		String username = in.nextLine();
		UserToken token = user.getToken(username);

		
	}
}
