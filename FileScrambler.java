import java.io.*;
import java.util.*;


public class FileScrambler
{
	public static final int DATE_SIZE = 46;
	public static final int INT_BYTE_SIZE = Integer.SIZE/8;
	//These two variables hold the size of the date and the int that are in the header of all the files
	//We keep track of these because we don't want to delete the header so the file appears 
	//uncompromised until it is opened
	
	public static void main(String[] args)
	{
		Scanner in = new Scanner(System.in);
		System.out.println("Please enter the path of the file\n");
		
		try
		{
			File theFile = new File(in.nextLine());
			int length = (int) theFile.length();
			
			FileInputStream fis = new FileInputStream(theFile);
			
			byte[] wholeFile = new byte[length];
			byte[] header;
			byte[] rawFile;
			
			fis.read(wholeFile);
			header = Arrays.copyOfRange(wholeFile, 0, DATE_SIZE+INT_BYTE_SIZE);
			rawFile = Arrays.copyOfRange(wholeFile, DATE_SIZE+INT_BYTE_SIZE, length);
			//We have now split the file into the header, which we wish to preserver
			//and the file contents, which we wish to scramble
			ArrayList<Byte> bigRawFile = new ArrayList<Byte>();
			for(int i = 0; i<rawFile.length; i++)
			{
				bigRawFile.add(new Byte(rawFile[i]));
			}
			
			Collections.shuffle(bigRawFile);
			
			for(int i = 0; i<rawFile.length; i++)
			{
				rawFile[i] = bigRawFile.get(i);
			}
			
			System.arraycopy(header, 0, wholeFile, 0, header.length);
			System.arraycopy(rawFile, 0, wholeFile, header.length, rawFile.length);
			
			FileOutputStream fos = new FileOutputStream(theFile);
			fos.write(wholeFile);
			
			
		}
		catch(Exception e)
		{
			e.printStackTrace();
			System.exit(-1);
		}
		
	}
}