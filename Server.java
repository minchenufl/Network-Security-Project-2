import java.io.*;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

/**
 * This class implements the functions of a server in this project.
 * The server accepts a connection from a client, and allows the client
 * to register as a new user or authenticate itself.
 * @author Min Chen
 *
 */

public class Server 
{
  public final static int EMPLOYEE_NUMBER = 100;
	public final static int PORT = 9000;
	
	public static void main(String[] args) throws IllegalBlockSizeException, BadPaddingException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, ClassNotFoundException
	{
		Scanner in = new Scanner(System.in);
		System.out.print("Employee Records: ");
		String recordFile = in.nextLine();
		System.out.print("Decryption Key:");
		byte[] key = in.nextLine().getBytes();
		
		//String recordFile = "EmREC.db";
		//byte[] key = "Go Gators".getBytes();

		Employee[] employees = loadFile(recordFile, key);	//load the employee records to memory
		
		System.out.print("Starting server...");				//start the server
		ServerSocket sSocket = new ServerSocket(PORT);
		System.out.println(" [Success!] [Port: " + PORT +"]");
		System.out.println("Waiting for connections...");
		Socket cSocket = sSocket.accept();					//wait for connection request
		System.out.println("Incoming connection [IP:" + cSocket.getInetAddress() + "]" + "[Port:" + cSocket.getPort() + "]");	
		
		//receive step 1-------------------------
		ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(cSocket.getInputStream()));
		String m1 = (String) ois.readObject();
		System.out.println("INCOMING-> " + m1);
		//---------------------------------------
		
		//step 2---------------------------------
		KeyPair kp = genKeys("Go Gators");					//generate a pair of RSA keys	
		PublicKey publicKey = kp.getPublic();
		PrivateKey privateKey = kp.getPrivate();
		//System.out.println(publicKey.toString());
		
		ObjectOutputStream oos = new ObjectOutputStream(cSocket.getOutputStream());
		oos.writeObject(publicKey);							//send public key to the client
		oos.flush();
		
		MessageDigest md5 = MessageDigest.getInstance("MD5");	//generate a nounce, to prevent from replay attack
		byte[] msgDigest = md5.digest(Long.toString(System.currentTimeMillis()).getBytes());
		Random gen = new Random();
		int partDigest = (msgDigest[0] & 0xff) | ((msgDigest[1] & 0xff) << 8) | ((msgDigest[2] & 0xff) << 16);
		partDigest += gen.nextInt(100);
		msgDigest[0] = (byte) (partDigest & 0xff);
		msgDigest[1] = (byte) ((partDigest & 0xff00) << 8);
		msgDigest[2] = (byte) ((partDigest & 0xff0000) << 16);
		
		byte[] signedNounce = signMessage(msgDigest, privateKey);
		String sn = new String (signedNounce, "ISO-8859-1");	//sign the nounce
		
		//System.out.println(sn);
		oos.writeObject(sn);
		oos.flush();
		System.out.println("SENT-> <" + publicKey.toString() + ">," + sn);
		//---------------------------------------

		//receive step 3-------------------------
		String m3 = (String) ois.readObject();
		System.out.println("INCOMING->" + m3);
		
		byte[] b = m3.getBytes("ISO-8859-1");
		m3 = new String(decryptMessage(b, privateKey), "ISO-8859-1");
		String[] temp = m3.split("@");
		String mode = temp[0];
		byte[] digestCopy = temp[1].getBytes("ISO-8859-1");
		
		System.out.print("Deciphering:: " + mode + ", 0x");
		
		for(int i=0; i<digestCopy.length; i++)
			System.out.printf("%x", digestCopy[i]);
		System.out.println(" ::");
		//---------------------------------------

		//step 4---------------------------------
		if(isValidNounce(msgDigest, digestCopy))			//check whether the received nounce is valid (replay attack)
		{
			b = signMessage("OK".getBytes("ISO-8859-1"), privateKey);
			String m4 = new String(b, "ISO-8859-1");
			System.out.println("SENT->" + m4 + " [UNSIGNED VERSION: SENT->OK]");
			oos.writeObject(m4);
			oos.flush();
		}
		
		else
		{
			b = signMessage("Invalid nounce".getBytes("ISO-8859-1"), privateKey);
			String m4 = new String(b, "ISO-8859-1");
			System.out.println("SENT->" + m4 + " [UNSIGNED VERSION: SENT->Invalid nounce]");
			oos.writeObject(m4);
			oos.flush();
			cSocket.close();
			sSocket.close();
			System.exit(1);
		}
		//---------------------------------------
		
		if(mode.equals("REG"))
		{
			System.out.println("Switching to REG Mode!");
			//receive step 5---------------------
			boolean validUsername = false;
			String m5, ssn = null, userName = null;
			int id = 0;
			Employee e;
			while(!validUsername)							//check the whether the username is available 
			{
				m5 = (String) ois.readObject();
				System.out.println("INCOMING->" + m5);
				b = m5.getBytes("ISO-8859-1");
				m5 = new String(decryptMessage(b, privateKey), "ISO-8859-1");
				temp = m5.split("@");
				id = Integer.parseInt(temp[0]);
				ssn = temp[1];
				userName = temp[2];
				digestCopy = temp[3].getBytes("ISO-8859-1");
				
				System.out.print("Deciphering:: " + "ID: " + id + ", SSN: " + ssn + ", Username: " + 
				userName + ", 0x");
				for(int i=0; i<digestCopy.length; i++)
					System.out.printf("%x", digestCopy[i]);
				System.out.println();
				
				e = searchUsername(employees, userName);
				if(e == null || (e.getId() == id && e.getSsn().equals(ssn)))     //the username does not exist or is chosen by the same user
				{	validUsername = true;
					b = signMessage("Username is available".getBytes("ISO-8859-1"), privateKey);
					String s = new String(b, "ISO-8859-1");
					System.out.println("SENT->" + s + " [UNSIGNED VERSION: Username is available]");
					oos.writeObject(s);
					oos.flush();
				}
				else
				{
					b = signMessage("Username already exists!".getBytes("ISO-8859-1"), privateKey);
					String s = new String(b, "ISO-8859-1");
					System.out.println("SENT->" + s + " [UNSIGNED VERSION: Username already exists!]");
					oos.writeObject(s);
					oos.flush();
				}
			}
			e = searchEmployees(employees, id, ssn);
			//-----------------------------------
			
			//step 6-----------------------------
			if(e != null && isValidNounce(msgDigest, digestCopy))
			{
				e.setUsername(userName);
				b = signMessage("OK".getBytes("ISO-8859-1"), privateKey);
				String m6 = new String(b, "ISO-8859-1");
				System.out.println("SENT->" + m6 + " [UNSIGNED VERSION: OK]");
				oos.writeObject(m6);
				oos.flush();
			}
			
			else
			{
				b = signMessage("Reject".getBytes("ISO-8859-1"), privateKey);
				String m6 = new String(b, "ISO-8859-1");
				System.out.println("SENT->" + m6 + " [UNSIGNED VERSION: Reject]");
				oos.writeObject(new String(b, "ISO-8859-1"));
				oos.flush();
				cSocket.close();
				sSocket.close();
				System.exit(1);
			}
			//-----------------------------------
			
			
			//step 7 and 8 ----------------------
			boolean strongEnough = false;
			while(!strongEnough)
			{
				String m7 = (String) ois.readObject();
				System.out.println("INCOMING->" + m7);
				
				b = m7.getBytes("ISO-8859-1");
				m7 = new String(decryptMessage(b, privateKey), "ISO-8859-1");
				temp = m7.split("@");
				id = Integer.parseInt(temp[0]);
				ssn = temp[1];
				String passWord = temp[2];
				digestCopy = temp[3].getBytes("ISO-8859-1");
				System.out.print("Deciphering:: " + "ID: " + id + ", SSN: " + ssn + ", Password: " + 
						passWord + ", 0x");
				for(int i=0; i<digestCopy.length; i++)
					System.out.printf("%x", digestCopy[i]);
						System.out.println();
				
				
				e = searchEmployees(employees, id, ssn);
				
				if(e == null || !isValidNounce(msgDigest, digestCopy))
				{
					b = signMessage("Reject".getBytes("ISO-8859-1"), privateKey);
					String m8 = new String(b, "ISO-8859-1");
					System.out.println("SENT->" + m8 + " [UNSIGNED VERSION: Reject]");
					oos.writeObject(m8);
					oos.flush();
					cSocket.close();
					sSocket.close();
					System.exit(1);
				}
				
				strongEnough = isPswStrong(passWord);
				if(strongEnough)
				{
					b = signMessage("OK".getBytes("ISO-8859-1"), privateKey);
					String m8 = new String(b, "ISO-8859-1");
					System.out.println("SENT->" + m8 + " [UNSIGNED VERSION: OK]");
					oos.writeObject(m8);
					oos.flush();
				}
				
				else
				{
					b = signMessage("Password is too weak".getBytes("ISO-8859-1"), privateKey);
					String m8 = new String(b, "ISO-8859-1");
					System.out.println("SENT->" + m8 + " [UNSIGNED VERSION: Password is too weak]");
					oos.writeObject(m8);
					oos.flush();
				}
			}
			//-----------------------------------
			
			//receive step 9---------------------			//retrieve the PIN selected by the user
			String m9 = (String) ois.readObject();
			System.out.println("INCOMING->" + m9);
			
			b = m9.getBytes("ISO-8859-1");
			m9 = new String(decryptMessage(b, privateKey), "ISO-8859-1");
			temp = m9.split("@");
			
			String passWord = temp[1];
			byte[] result = temp[2].getBytes("ISO-8859-1");
			
			b = md5.digest(passWord.getBytes());
			String passPhrase = new String(b, "ISO-8859-1");
			TEA tea = new TEA(passPhrase);
			
			int[] v = new int[2];
			v[0] = (result[0] & 0xff) | ((result[1] & 0xff) << 8) | ((result[2] & 0xff) << 16) | ((result[3] & 0xff) << 24);
			v[1] = (result[4] & 0xff) | ((result[5] & 0xff) << 8) | ((result[6] & 0xff) << 16) | ((result[7] & 0xff) << 24);
			
			tea.decryptBlock(v);
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
			tea.decryptBlock(v);
			result[8] = (byte) (v[0] & 0xff);
			result[9] = (byte) ((v[0] & 0xff00) >>> 8);
			result[10] = (byte) ((v[0] & 0xff0000) >>> 16);
			result[11] = (byte) ((v[0] & 0xff000000) >>> 24);
			result[12] = (byte) (v[1] & 0xff);
			result[13] = (byte) ((v[1] & 0xff00) >>> 8);
			result[14] = (byte) ((v[1] & 0xff0000) >>> 16);
			result[15] = (byte) ((v[1] & 0xff000000) >>> 24);
			
			int pin = ((digestCopy[0] & 0xff) ^ (result[0] & 0xff)) |(((digestCopy[1] & 0xff) ^ (result[1] & 0xff)) << 8);
			System.out.println("Deciphering:: " + "Username: " + userName + ", Password: " + passWord + ", " +
					"PIN" + pin);
			//------------------------
			
			//step 10-----------------
			b = signMessage("REG-SUCC".getBytes("ISO-8859-1"), privateKey);
			String m10 = new String(b, "ISO-8859-1");
			System.out.println("SENT->" + m10 + "[UNSIGNED VERSION: REG-SUCC]");
			oos.writeObject(m10);
			oos.flush();
			
			e.setUsername(userName);
			e.setPswhash(passWord.hashCode());
			e.setPin(pin);
			
			updateFile(employees, recordFile, key);			//update the employee records with the new registered employee
		}
		
		else if(mode.equals("AUTH"))
		{
			System.out.println("Switching to AUTH Mode!");
			
			//receive step 5---------------------
			String m5 = (String) ois.readObject();
			System.out.println("INCOMING->" + m5);
			
			b = m5.getBytes("ISO-8859-1");
			m5 = new String(decryptMessage(b, privateKey), "ISO-8859-1");
			temp = m5.split("@");
			String userName = temp[0];
			digestCopy = temp[1].getBytes("ISO-8859-1");
			System.out.print("Deciphering:: " + "Username: " + userName + ", 0x");
			for(int i=0; i<digestCopy.length; i++)
				System.out.printf("%x", digestCopy[i]);
			System.out.println();
			
			Employee e = searchUsername(employees, userName);
			//-----------------------------------
			
			//step 6-----------------------------			//verify the username is valid
			if(e != null && isValidNounce(msgDigest, digestCopy))
			{
				b = signMessage("OK".getBytes("ISO-8859-1"), privateKey);
				String m6 = new String(b, "ISO-8859-1");
				System.out.println("SENT->" + m6 + "[UNSIGNED VERSION: OK]");
				oos.writeObject(m6);
				oos.flush();
			}
			
			else
			{
				b = signMessage("Reject".getBytes("ISO-8859-1"), privateKey);
				String m6 = new String(b, "ISO-8859-1");
				System.out.println("SENT->" + m6 + "[UNSIGNED VERSION: Reject]");
				oos.writeObject(m6);
				oos.flush();
				cSocket.close();
				sSocket.close();
				System.exit(1);
			}
			//-----------------------------------
			
			//receive step 7---------------------			
			String m7 = (String) ois.readObject();
			System.out.println("INCOMING->" + m7);
			b = m7.getBytes("ISO-8859-1");
			m7 = new String(decryptMessage(b, privateKey), "ISO-8859-1");
			temp = m7.split("@");
			userName = temp[0];
			String passWord = temp[1];
			digestCopy = temp[2].getBytes("ISO-8859-1");
			System.out.print("Deciphering:: " + "Username: " + userName + ", Password: " + 
					passWord + ", 0x");
			for(int i=0; i<digestCopy.length; i++)
				System.out.printf("%x", digestCopy[i]);
					System.out.println();
			
			//step 8-----------------------------			//verify the password is correct
			if(passWord.hashCode() == e.getPswhash() && isValidNounce(msgDigest, digestCopy))
			{
				b = signMessage("OK".getBytes("ISO-8859-1"), privateKey);
				String m8 = new String(b, "ISO-8859-1");
				System.out.println("SENT->" + m8 + "[UNSIGNED VERSION: OK]");
				oos.writeObject(m8);
				oos.flush();
			}
			
			else
			{
				b = signMessage("Reject".getBytes("ISO-8859-1"), privateKey);
				String m8 = new String(b, "ISO-8859-1");
				System.out.println("SENT->" + m8 + "[UNSIGNED VERSION: Reject]");
				oos.writeObject(m8);
				oos.flush();
				cSocket.close();
				sSocket.close();
				System.exit(1);
			}
			//------------------------
			
			//receive step 9----------						//retrieve the PIN selected by the user
			String m9 = (String) ois.readObject();
			System.out.println("INCOMING->" + m9);
			b = m9.getBytes("ISO-8859-1");
			m9 = new String(decryptMessage(b, privateKey), "ISO-8859-1");
			temp = m9.split("@");
			userName = temp[0];
			passWord = temp[1];
			byte[] result = temp[2].getBytes("ISO-8859-1");
			
			b = md5.digest(passWord.getBytes());
			String passPhrase = new String(b, "ISO-8859-1");
			TEA tea = new TEA(passPhrase);
			
			int[] v = new int[2];
			v[0] = (result[0] & 0xff) | ((result[1] & 0xff) << 8) | ((result[2] & 0xff) << 16) | ((result[3] & 0xff) << 24);
			v[1] = (result[4] & 0xff) | ((result[5] & 0xff) << 8) | ((result[6] & 0xff) << 16) | ((result[7] & 0xff) << 24);
			
			tea.decryptBlock(v);
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
			tea.decryptBlock(v);
			result[8] = (byte) (v[0] & 0xff);
			result[9] = (byte) ((v[0] & 0xff00) >>> 8);
			result[10] = (byte) ((v[0] & 0xff0000) >>> 16);
			result[11] = (byte) ((v[0] & 0xff000000) >>> 24);
			result[12] = (byte) (v[1] & 0xff);
			result[13] = (byte) ((v[1] & 0xff00) >>> 8);
			result[14] = (byte) ((v[1] & 0xff0000) >>> 16);
			result[15] = (byte) ((v[1] & 0xff000000) >>> 24);
			
			int pin = ((digestCopy[0] & 0xff) ^ (result[0] & 0xff)) |(((digestCopy[1] & 0xff) ^ (result[1] & 0xff)) << 8);
			System.out.print("Deciphering:: " + "Username: " + userName + ", Password: " + passWord + ", " +
					"PIN" + pin);
			//------------------------
			
			//step 10-----------------
			String m10 = null;
			if(pin == e.getPin())
			{
				b = signMessage("AUTH-SUCC".getBytes("ISO-8859-1"), privateKey);
				m10 = new String(b, "ISO-8859-1");
				System.out.println("SENT->" + m10 + "[UNSIGNED VERSION: AUTH-SUCC]");
			}
			
			else
			{
				b = signMessage("AUTH-FAIL".getBytes("ISO-8859-1"), privateKey);
				m10 = new String(b, "ISO-8859-1");
				System.out.println("SENT->" + m10 + "[UNSIGNED VERSION: AUTH-FAIL]");
			}
			oos.writeObject(m10);
			oos.flush();
			//-----------------------------------
		}
		
		else												//deal with the case that wrong mode is entered
		{
			
			System.out.println("Error! No such mode!");
			b = signMessage("Error! No such mode!".getBytes("ISO-8859-1"), privateKey);
			oos.writeObject(new String(b, "ISO-8859-1"));
			System.exit(1);
		}
		
		in.close();
		ois.close();
		oos.close();
		cSocket.close();
		sSocket.close();
	}
	
	/**
	 * This method decrypts the encrypted file and load the employees' records to memory
	 * @param recordFile file name
	 * @param key administor's key that was used to encrypt the file
	 * @return all employee records
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws FileNotFoundException
	 */
	public static Employee[] loadFile(String recordFile, byte[] key) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, FileNotFoundException
	{	
		Cipher cipher = null;
		try{
			SecureRandom sr = new SecureRandom();
			DESKeySpec dks = new DESKeySpec(key);
			SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
			SecretKey desKey = skf.generateSecret(dks);
			cipher = Cipher.getInstance("DES");
			cipher.init(Cipher.DECRYPT_MODE, desKey, sr);
		}catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException ex) {
		    System.err.println("[CRITICAL] Incryption chiper error");
		}
		
		System.out.print("Analyzing file...Loading[|]");
		Scanner fr = new Scanner(new File(recordFile));
		String record;
		String[] tempBytes;
		Employee[] employees = new Employee[EMPLOYEE_NUMBER];
		int index = 0;
		String[] tempData;
		while(fr.hasNextLine())
		{
			record = fr.nextLine();
			tempBytes = record.split("\t");
			byte[] cipherText = new byte[tempBytes.length];
			
			for(int i=0; i<tempBytes.length; i++)
				cipherText[i] = Byte.parseByte(tempBytes[i]);
			
			record = new String(cipher.doFinal(cipherText), "UTF8");
			//System.out.println(record);
			tempData = record.split("@");
			employees[index] = new Employee(Integer.parseInt(tempData[0]), tempData[1]);
			employees[index].setUsername(tempData[2]);
			employees[index].setPswhash(Integer.parseInt(tempData[3]));
			employees[index].setPin(Integer.parseInt(tempData[4]));	
			
			//System.out.println(employees[index].getId());
			index++;
			if(index % 10 == 0)
				System.out.print("=");
		}
		
		System.out.println(" 100%]");
		fr.close();
		return employees;
	}
	
	/**
	 * This method encrypts all employee records and write them back to the file.
	 * It is used when an employee completes his/her registration.
	 * @param employees employee records
	 * @param recordFile file name
	 * @param key administor's key 
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws FileNotFoundException
	 */
	public static void updateFile(Employee[] employees, String recordFile, byte[] key) throws IllegalBlockSizeException, BadPaddingException, FileNotFoundException
	{
		PrintWriter pw = new PrintWriter (new File(recordFile));
		Cipher cipher = null;
		
		try{
			SecureRandom sr = new SecureRandom();
			DESKeySpec dks = new DESKeySpec(key);
			SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
			SecretKey desKey = skf.generateSecret(dks);
			cipher = Cipher.getInstance("DES");
			cipher.init(Cipher.ENCRYPT_MODE, desKey, sr);
		}catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException ex) {
		    System.err.println("[CRITICAL] Incryption chiper error!");
		}
		
		byte [] plainText;
		byte [] cipherText = null;
		for(Employee e: employees)
		{
			plainText = e.getRecord().getBytes();
			cipherText = cipher.doFinal(plainText);
			for(int j=0; j<cipherText.length; j++)
				pw.print(cipherText[j] + "\t");
			pw.println();
		}
		
		pw.close();
	}
	
	/**
	 * Search a certain employee with his/her ID and SSN
	 * @param employees all employee records
	 * @param id the employee's ID
	 * @param ssn the employee's SSN
	 * @return the employee if it is found, otherwise, return null
	 */
	public static Employee searchEmployees(Employee[] employees, int id, String ssn)
	{	
		for(Employee e : employees)
		{
			if(e.getId() == id && e.getSsn().equals(ssn))
				return e;
		}
		
		return null;
	}
	
	/**
	 * Search a certain employee with his/her username
	 * @param employees all employee records
	 * @param userName the employee's username
	 * @return
	 */
	public static Employee searchUsername(Employee[] employees, String userName)
	{
		for(Employee e : employees)
		{
			if(e.getUsername().equals(userName))
				return e;
		}
		
		return null;
	}
	
	/**
	 * Generate a RSA key pair
	 * @param keyInfo secure information used to generate the key pair
	 * @return <Publickey, PrivateKey>
	 * @throws NoSuchAlgorithmException
	 */
	public static KeyPair genKeys(String keyInfo) throws NoSuchAlgorithmException
	{
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		SecureRandom sr = new SecureRandom();
		sr.setSeed(keyInfo.getBytes());
		keygen.initialize(512, sr);
		return keygen.generateKeyPair();
	}
	
	/**
	 * Sign a message with the private key
	 * @param message the message to be signed
	 * @param key the server's privates key
	 * @return the signed message
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] signMessage(byte[] message, PrivateKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(message);
	}

	/**
	 * Decrypt an message using the private key	
	 * @param message message that is encrypted by the client using the server's public key
	 * @param key the server's private key
	 * @return the decrypted message
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] decryptMessage(byte[] message, PrivateKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(message);
	}
	
	/**
	 * Verify whether the nounce is valid or not
	 * @param msgDigest the nounce generated by the server
	 * @param rcvDigest the nounce sent from the client
	 * @return true if the nounce is valid; otherwise, return false
	 */
	public static boolean isValidNounce(byte[]msgDigest, byte[]rcvDigest)
	{
		int partDigest = (msgDigest[0] & 0xff) | ((msgDigest[1] & 0xff) << 8) | ((msgDigest[2] & 0xff) << 16);
		int rcvPartDigest = (rcvDigest[0] & 0xff) | ((rcvDigest[1] & 0xff) << 8) | ((rcvDigest[2] & 0xff) << 16);
		
		return(rcvPartDigest == (partDigest + 1));
	}
	
	/**
	 * Test whether the password is strong enough
	 * @param passWord password entered by the user
	 * @return true if the password meet the strength requirement; otherwise, return false
	 */
	public static boolean isPswStrong(String passWord)
	{
		int strength = 0;
		if(passWord.length() < 5)
			strength = 0;
		else
		{
			strength = 2 * passWord.length();
			
			for(int i=0; i<passWord.length(); i++)
			{
				//for numerals add extra 1 to strength
				if('0' <= passWord.charAt(i) && passWord.charAt(i) <= '9')  
					strength += 1;
				
				//non alpha-numeric characters add extra 2 to strength
				else if(!(('A' <= passWord.charAt(i) && passWord.charAt(i) <= 'Z') ||
						('a' <= passWord.charAt(i) && passWord.charAt(i) <= 'z')))
					strength += 2;	
			}
			
			//if a CAPITAL letter follows a small case letter, add extra 1 to the strength
			for(int i=0; i<passWord.length()-1; i++)
			{
				if(('A' <= passWord.charAt(i) && passWord.charAt(i) <= 'Z')
					&& ('a' <= passWord.charAt(i+1) && passWord.charAt(i) <= 'z'))
					strength ++;
			}
		}
		
		return (strength >= 16);
	}

}
