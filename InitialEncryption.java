import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;

/**
 * This class is used to create an encrypted database for all employees records.
 * Initially, each employee only have two fields, ID and SSN. We only need to
 * run it once to obtain the file "EmREC.db".
 * @author Min Chen
 *
 */
public class InitialEncryption 
{
  public static void main(String[] args) throws FileNotFoundException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException
	{
		final int EMPLOYEE_NUMBER = 100;
		final int INITIAL_ID = 1691;
		final String INITIAL_SSN = "123-45-6789";
		
		String[] temp = INITIAL_SSN.split("-");
		String s = "";
		for(int i=0; i<temp.length; i++)
		{
			s += temp[i];
		}
		
		int ssnInteger = Integer.parseInt(s);
		
		Employee[] employees = new Employee[EMPLOYEE_NUMBER];
		
		String ssn, s1, s2, s3;
		PrintWriter pw = new PrintWriter (new File("EmREC.db"));
		
		byte[] key = "Go Gators".getBytes();        		// This is the administrator's key that can decrypt "EmREC.db"
		Cipher cipher = null;
			
		try{												// Use DES to encrypt those records
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
		for(int i=0; i<EMPLOYEE_NUMBER; i++)
		{
			ssn = Integer.toString(ssnInteger + i);
			s1 = ssn.substring(0, 3);
			s2 = ssn.substring(3, 5);
			s3 = ssn.substring(5, 9);
			ssn = s1 + "-" + s2 + "-" + s3;
			employees[i] = new Employee(INITIAL_ID + i, ssn);	//initialize 100 records
			plainText = employees[i].getRecord().getBytes();
			/*for(int j=0; j<plainText.length; j++)
				System.out.print(plainText[j] + "\t");
			System.out.println();*/
			
			cipherText = cipher.doFinal(plainText);			//encrypt and write to a file
			for(int j=0; j<cipherText.length; j++)
				pw.print(cipherText[j] + "\t");
			pw.println();
		}
		
		pw.close();
		
		
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
		
		
		Scanner fr = new Scanner(new File("EmREC.db"));
		String record;
		String[] tempBytes;
		while(fr.hasNextLine())								// read and decrypt, just for test
		{
			record = fr.nextLine();
			tempBytes = record.split("\t");
			for(int i=0; i<tempBytes.length; i++)
				cipherText[i] = Byte.parseByte(tempBytes[i]);
			
			/*for(int j=0; j<cipherText.length; j++)
				System.out.print(cipherText[j] + "\t");
			System.out.println();*/
			plainText = cipher.doFinal(cipherText);
			record = new String(plainText, "UTF8");
			System.out.println(record);
		}
		fr.close();
	}
}
