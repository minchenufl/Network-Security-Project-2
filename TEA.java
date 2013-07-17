/**
 * This class implements the TEA algorithm, which acts as the 
 * encrypt/decrypt algorithm in this project.
 * @author Min Chen
 *
 */
public class TEA 
{
  private byte[] keyinBytes;         
	private int[] key = new int[4];     //128-bit key, represented by 4 integers
	private int paddingLength; 
	
	
	public TEA(String passPhrase)
	{
		if(passPhrase.length()>16)      //128-bit key, need 16 characters
			passPhrase = passPhrase.substring(0, 16);
		else
			{
				paddingLength = 16 - passPhrase.length();
				for(int i=0; i<paddingLength; i++)
				{
					passPhrase += "@";
				}
			}
		
		keyinBytes = passPhrase.getBytes();
		//System.out.println(keyinBytes.length);
		for(int i=0; i<4; i++)
			key[i] = (keyinBytes[4*i] & 0xff) | ((keyinBytes[4*i+1] & 0xff) << 8) | ((keyinBytes[4*i+2] & 0xff) << 16) | ((keyinBytes[4*i+3] & 0xff) << 24);
	}
	
	
	/**
	 * Encryption method of TEA.
	 * @param v represents a 64-bit plaintext block
	 */
	public void encryptBlock(int[] v) 
	{
		int v0 = v[0], v1 = v[1], sum = 0;
		int delta = 0x9e3779b9;
		for(int i=0; i<32; i++)
		{
			sum += delta;
	        v0 += ((v1<<4) + key[0]) ^ (v1 + sum) ^ ((v1>>5) + key[1]);
	        v1 += ((v0<<4) + key[2]) ^ (v0 + sum) ^ ((v0>>5) + key[3]);  
		}
		
		v[0] = v0;
		v[1] = v1;
	}
	
	/**
	 * Decryption method of TEA.
	 * @param v represents a 64-bit cipher block
	 */
	public void decryptBlock(int[] v)
	{
		int v0=v[0], v1=v[1], sum=0xC6EF3720;
		int delta=0x9e3779b9;                     
		for (int i=0; i<32; i++) 
		{                                             
	        v1 -= ((v0<<4) + key[2]) ^ (v0 + sum) ^ ((v0>>5) + key[3]);
	        v0 -= ((v1<<4) + key[0]) ^ (v1 + sum) ^ ((v1>>5) + key[1]);
	        sum -= delta;                                   
	    }                                         
	    v[0]=v0; v[1]=v1;
	}

}
