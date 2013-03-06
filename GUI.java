import java.net.Socket;
import java.io.*;
import java.util.*;
import javax.swing.*;
import java.awt.*;

public class GUI extends JFrame
{
	public static void main(String[] args)
	{
		if(args.length != 2)
			new GUI(8766, 4321);
		else
			new GUI(Integer.parseInt(args[0]), Integer.parseInt(args[1]));
	}

	public GUI(int groupPort, int filePort)
	{
		JPanel window = new JPanel(new GridBagLayout());
		this.setContentPane(window);
		window.add(new JLabel("GUI"));
		
		setVisible(true);
	}
}