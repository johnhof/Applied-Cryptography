import java.net.Socket;
import java.io.*;
import java.util.*;

public class UI
{
	public static void main(String[] args)
	{
		//GroupServer is named "ALPHA" and is on 8766
		//FileServer is named "FilePile" and is on 4321

		System.out.println("Attempting to connect to GroupServer.");
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
		do{	
			System.out.println("What would you like to do now?");//Queries the user
			System.out.println("Type F for File Server operations or G for Group Server operations.");
			String input = n.nextLine();
			if(input.equals("F") || input.equals("f"))
			{
				System.out.println("");
			}
			else if(input.equals("G") || input.equals("g"))
			{
				System.out.print("Would you like to:\n1-Create a User\n2-Delete a User\n");
				System.out.print("3-Create a Group\n4-Delete a Group\n5-List a Group's Members");
				System.out.print("\n6-Add to a Group\n7-Delete from a Group\nPlease enter your selection's");
				System.out.print("numeric value.\n");
				input = n.nextLine();
			}
		} while(true);//forever
	}
}
