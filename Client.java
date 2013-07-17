import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Scanner;
import java.security.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * This class implements the function of a client.
 * It can be used for registration or authentication.
 * @author Min Chen
 *
 */

public class Client 
{
  public static void main(String[] args) throws UnknownHostException, IOException, ClassNotFoundException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		Scanner in = new Scanner(System.in);
		System.out.print("Enter Server IP: ");
		String ip = in.nextLine();
		//String ip = "127.0.0.1";
		
		System.out.print("Enter Server Port: ");
		int port = in.nextInt();
		//int port = 9000;
		
		Socket socket = new Socket(ip, port);				//connect to the server
	
		//step 1---------------------------------
		ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
		oos.writeObject("Hello");
		oos.flush();
		System.out.println("SENT-> Hello");					//say "hello" to server 
		//----------------------------
		
		//receive step 2-------------------------
		ObjectInputStream ois = null;	
		ois = new ObjectInputStream(socket.getInputStream());
		PublicKey publicKey= (PublicKey) ois.readObject();	//receive server's public key
		System.out.print("Server response: " + "<" + publicKey.toString() + ">, ");
		
		String m2 = (String) ois.readObject();				// receive a nounce from server
		System.out.println(m2);
		
		byte[] msgDigest = verifySignature (m2.getBytes("ISO-8859-1"), publicKey);
		System.out.print("Verifying: 0x");
		for(int i=0; i<msgDigest.length; i++)
			System.out.printf("%x", msgDigest[i]);
		System.out.println();
		//---------------------------------------
		
					
		System.out.println("----------------------------");	//choose registration/authentication
		System.out.println("1. New registration");
		System.out.println("2. Authentication");
		System.out.println("----------------------------");
		System.out.print("Choice (1 or 2):");
		
		int partDigest = (msgDigest[0] & 0xff) | ((msgDigest[1] & 0xff) << 8) | ((msgDigest[2] & 0xff) << 16);
		partDigest += 1;									//nounce + 1
		msgDigest[0] = (byte) (partDigest & 0xff);
		msgDigest[1] = (byte) ((partDigest & 0xff00) << 8);
		msgDigest[2] = (byte) ((partDigest & 0xff0000) << 16);
		
		
		int choice = in.nextInt();
		if(choice == 1)
		{
			//step 3-----------------------------
			String m3 = "REG@" + new String(msgDigest, "ISO-8859-1");		//send <REG, nounce+1> to server
			byte[] b = encryptMessage(m3.getBytes("ISO-8859-1"), publicKey);
			m3 = new String(b, "ISO-8859-1");
			
			//System.out.println("SENT->" + m3 + "[PLAIN: " + "REG@" + new String(msgDigest, "ISO-8859-1") +"]");
			oos.writeObject(m3);
			oos.flush();
			//-----------------------------------
			 
			//receive step 4---------------------			// server response
			String m4 = (String) ois.readObject();
			b = verifySignature(m4.getBytes("ISO-8859-1"), publicKey);
			m4 = new String(b, "ISO-8859-1");
			System.out.println("Server Response: " + m4);
			
			if(!m4.equals("OK"))
				System.exit(1);
			//-----------------------------------
			
			//step 5------------------
			System.out.println("Start new registration attempt...");
			System.out.print("Enter ID: ");
			int id = in.nextInt();
			//int id= 1692;
			System.out.print("Enter SSN: ");
			String ssn = in.nextLine();
			//String ssn = "123-45-6790";
			
			boolean validUsername = false;
			String userName = null, s;
			while(!validUsername)							//choose a username that is unique in the database
			{
				System.out.print("Choose a Username: ");
				userName = in.nextLine();
				System.out.println("Request is sent...");
				
				String m5 = id + "@" + ssn + "@" + userName + "@"  + new String(msgDigest, "ISO-8859-1");
				b = encryptMessage(m5.getBytes("ISO-8859-1"), publicKey);
				
				oos.writeObject(new String(b, "ISO-8859-1"));
				oos.flush();
				
				s = (String) ois.readObject();
				b = s.getBytes("ISO-8859-1");
				s = new String(verifySignature(b, publicKey), "ISO-8859-1");
				System.out.println(s);
				if(s.equals("Username is available"))
					validUsername = true;
			}
			//-----------------------------------
			
			//receive step 6---------------------			//server response
			String m6 = (String) ois.readObject();
			b = m6.getBytes("ISO-8859-1");
			m6 = new String(verifySignature(b, publicKey), "ISO-8859-1");
			System.out.println("Server Response: " + m6);
			
			if(!m6.equals("OK"))
			{
				ois.close();
				oos.close();
				socket.close();
				System.exit(1);
			}
			//-----------------------------------
			
			//step 7 and 8-----------------------
			boolean strongEnough = false;
			String passWord = null;
			while(!strongEnough)							//choose a password that meets the strength requirement
			{
				System.out.print("Enter a password that is strong enough: ");
				passWord = in.nextLine();
				String m7 = id + "@" + ssn + "@" + passWord + "@"  + new String(msgDigest, "ISO-8859-1");
				b = encryptMessage(m7.getBytes("ISO-8859-1"), publicKey);
				oos.writeObject(new String(b, "ISO-8859-1"));
				oos.flush();
				
				String m8 = (String) ois.readObject();
				b = m8.getBytes("ISO-8859-1");
				m8 = new String(verifySignature(b, publicKey), "ISO-8859-1");
				System.out.println("Server Response: " + m8);
				
				if(m8.equals("Reject"))
				{
					ois.close();
					oos.close();
					socket.close();
					System.exit(1);
				}
				
				else if(m8.equals("OK"))
					strongEnough = true;
			}
			//-----------------------------------
			
			//step 9-----------------------------			//select a 4-digit PIN
			System.out.print("Enter a 4-digit PIN: ");
			int pin = in.nextInt();
			
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			b = md5.digest(passWord.getBytes());
			String passPhrase = new String(b, "ISO-8859-1");
			TEA tea = new TEA(passPhrase);
			
			byte[] result = new byte[16];
			for(int i=0; i<16; i++)
			{
				result[i] = msgDigest[i];
			}
			
			result[0] ^= (pin & 0xff);
			result[1] ^= (pin & 0xff00) >>> 8;
			
			int[] v = new int[2];
			v[0] = (result[0] & 0xff) | ((result[1] & 0xff) << 8) | ((result[2] & 0xff) << 16) | ((result[3] & 0xff) << 24);
			v[1] = (result[4] & 0xff) | ((result[5] & 0xff) << 8) | ((result[6] & 0xff) << 16) | ((result[7] & 0xff) << 24);
			tea.encryptBlock(v);
			result[0] = (byte) (v[0] & 0xff);
			result[1] = (byte) ((v[0] & 0xff00) >>> 8);
			result[2] = (byte) ((v[0] & 0xff0000) >>> 16);
			result[3] = (byte) ((v[0] & 0xff000000) >>> 24);
			result[4] = (byte) (v[1] & 0xff);
			result[5] = (byte) ((v[1] & 0xff00) >>> 8);
			result[6] = (byte) ((v[1] & 0xff0000) >>> 16);
			result[7] = (byte) ((v[1] & 0xff000000) >>> 24);
			
			
			v[0] = (result[8] & 0xff) | ((result[9] & 0xff) << 8) | ((result[10] & 0xff) << 16) | ((result[11] & 0xff) << 24);
			v[1] = (result[12] & 0xff) | ((result[13] & 0xff) << 8) | ((result[14] & 0xff) << 16) | ((result[15] & 0xff) << 24);
			tea.encryptBlock(v);
			result[8] = (byte) (v[0] & 0xff);
			result[9] = (byte) ((v[0] & 0xff00) >>> 8);
			result[10] = (byte) ((v[0] & 0xff0000) >>> 16);
			result[11] = (byte) ((v[0] & 0xff000000) >>> 24);
			result[12] = (byte) (v[1] & 0xff);
			result[13] = (byte) ((v[1] & 0xff00) >>> 8);
			result[14] = (byte) ((v[1] & 0xff0000) >>> 16);
			result[15] = (byte) ((v[1] & 0xff000000) >>> 24);
			
			String m9 = userName + "@" + passWord + "@" + (new String(result, "ISO-8859-1"));
			b = encryptMessage(m9.getBytes("ISO-8859-1"), publicKey);
			oos.writeObject(new String(b, "ISO-8859-1"));
			oos.flush();
			//------------------------
			
			//receive step 10
			String m10 = (String) ois.readObject();			//server response
			b = m10.getBytes("ISO-8859-1");
			m10 = new String(verifySignature(b, publicKey), "ISO-8859-1");
			System.out.println("Server Response: " + m10);
		}
		
		else if(choice == 2)
		{
			//step 3-----------------------------
			String m3 = "AUTH@" + new String(msgDigest, "ISO-8859-1");	// send <AUTH, nounce+1> to server
			byte[] b = encryptMessage(m3.getBytes("ISO-8859-1"), publicKey);

			m3 = new String(b, "ISO-8859-1");
			oos.writeObject(m3);
			oos.flush();
			//-----------------------------------
			 
			//receive step 4---------------------			//server response
			String m4 = (String) ois.readObject();
			b = verifySignature(m4.getBytes("ISO-8859-1"), publicKey);
			m4 = new String(b, "ISO-8859-1");
			System.out.println("Server Response: " + m4);
			
			if(!m4.equals("OK"))
				System.exit(1);
			//-----------------------------------
			
			//step 5-----------------------------			//enter username for authentication
			System.out.println("Start authentication...");
			System.out.print("Enter your username: ");
			String userName = in.nextLine();
			
			String m5 = userName + "@"  + new String(msgDigest, "ISO-8859-1");
			b = encryptMessage(m5.getBytes("ISO-8859-1"), publicKey);
			
			oos.writeObject(new String(b, "ISO-8859-1"));
			oos.flush();
			//-----------------------------------
			
			//receive step 6---------------------			//server response
			String m6 = (String) ois.readObject();
			b = m6.getBytes("ISO-8859-1");
			m6 = new String(verifySignature(b, publicKey), "ISO-8859-1");
			System.out.println("Server Response: " + m6);
			
			if(!m6.equals("OK"))
			{
				ois.close();
				oos.close();
				socket.close();
				System.exit(1);
			}
			//-----------------------------------
			
			//step 7
			System.out.print("Enter your password: ");		//enter password
			String passWord = in.nextLine();
			String m7 = userName + "@" + passWord + "@"  + new String(msgDigest, "ISO-8859-1");
			b = encryptMessage(m7.getBytes("ISO-8859-1"), publicKey);
			oos.writeObject(new String(b, "ISO-8859-1"));
			oos.flush();
			//-----------------------------------
			
			//receive step 8---------------------			//server response
			String m8 = (String) ois.readObject();
			b = m8.getBytes("ISO-8859-1");
			m8 = new String(verifySignature(b, publicKey), "ISO-8859-1");
			System.out.println("Server Response: " + m8);
			
			if(m8.equals("Reject"))
			{
				ois.close();
				oos.close();
				socket.close();
				System.exit(1);
			}
			//-----------------------------------
			
			//step 9-----------------------------			//enter PIN
			System.out.print("Enter your 4-digit PIN: ");
			int pin = in.nextInt();
			
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			b = md5.digest(passWord.getBytes());
			String passPhrase = new String(b, "ISO-8859-1");
			TEA tea = new TEA(passPhrase);
			
			byte[] result = new byte[16];
			for(int i=0; i<16; i++)
			{
				result[i] = msgDigest[i];
			}
			
			result[0] ^= (pin & 0xff);
			result[1] ^= (pin & 0xff00) >>> 8;
			
			int[] v = new int[2];
			v[0] = (result[0] & 0xff) | ((result[1] & 0xff) << 8) | ((result[2] & 0xff) << 16) | ((result[3] & 0xff) << 24);
			v[1] = (result[4] & 0xff) | ((result[5] & 0xff) << 8) | ((result[6] & 0xff) << 16) | ((result[7] & 0xff) << 24);
			tea.encryptBlock(v);
			result[0] = (byte) (v[0] & 0xff);
			result[1] = (byte) ((v[0] & 0xff00) >>> 8);
			result[2] = (byte) ((v[0] & 0xff0000) >>> 16);
			result[3] = (byte) ((v[0] & 0xff000000) >>> 24);
			result[4] = (byte) (v[1] & 0xff);
			result[5] = (byte) ((v[1] & 0xff00) >>> 8);
			result[6] = (byte) ((v[1] & 0xff0000) >>> 16);
			result[7] = (byte) ((v[1] & 0xff000000) >>> 24);
			
			
			v[0] = (result[8] & 0xff) | ((result[9] & 0xff) << 8) | ((result[10] & 0xff) << 16) | ((result[11] & 0xff) << 24);
			v[1] = (result[12] & 0xff) | ((result[13] & 0xff) << 8) | ((result[14] & 0xff) << 16) | ((result[15] & 0xff) << 24);
			tea.encryptBlock(v);
			result[8] = (byte) (v[0] & 0xff);
			result[9] = (byte) ((v[0] & 0xff00) >>> 8);
			result[10] = (byte) ((v[0] & 0xff0000) >>> 16);
			result[11] = (byte) ((v[0] & 0xff000000) >>> 24);
			result[12] = (byte) (v[1] & 0xff);
			result[13] = (byte) ((v[1] & 0xff00) >>> 8);
			result[14] = (byte) ((v[1] & 0xff0000) >>> 16);
			result[15] = (byte) ((v[1] & 0xff000000) >>> 24);
			
			String m9 = userName + "@" + passWord + "@" + (new String(result, "ISO-8859-1"));
			b = encryptMessage(m9.getBytes("ISO-8859-1"), publicKey);
			oos.writeObject(new String(b, "ISO-8859-1"));
			oos.flush();
			//-----------------------------------
			
			//receive step 10--------------------			//server response
			String m10 = (String) ois.readObject();
			b = m10.getBytes("ISO-8859-1");
			m10 = new String(verifySignature(b, publicKey), "ISO-8859-1");
			System.out.println("Server Response: " + m10);
			//-----------------------------------
			
		}
		
		else												//deal with the case that wrong mode is entered
		{
			String m3 = "WRONG MODE@" + new String(msgDigest, "ISO-8859-1");
			byte[] b = encryptMessage(m3.getBytes("ISO-8859-1"), publicKey);

			m3 = new String(b, "ISO-8859-1");
			oos.writeObject(m3);
			oos.flush();
		
			
			String s = (String) ois.readObject();
			s = new String(verifySignature(s.getBytes("ISO-8859-1"), publicKey), "ISO-8859-1");
			
			s = (String) ois.readObject();
			s = new String(verifySignature(s.getBytes("ISO-8859-1"), publicKey), "ISO-8859-1");
			
			System.out.println(s);
			System.exit(1);
		}
		
		in.close();
		ois.close();
		oos.close();
		socket.close();
		
	}
	
	
	/**
	 * This function verifies the RSA signature of the server
	 * @param message received message from the server
	 * @param key server's public key
	 * @return the decrypted result using server's public key
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] verifySignature(byte[] message, PublicKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(message);
	}
	
	/**
	 * This function encrypt a message use the server's public key
	 * @param message message to be encrypted
	 * @param key server's public key
	 * @return the encrypted message
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] encryptMessage(byte[] message, PublicKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(message);
	}

}
