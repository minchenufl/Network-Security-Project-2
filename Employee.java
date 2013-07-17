/**
 * This class implements employee record
 * @author Min Chen
 *
 */
public class Employee
{
  private int id;
	private String ssn;
	private String userName;
	private int pswHash;
	private int pin;
	
	/**
	 * Constructor, initially only an employee's ID and SSN are stored
	 * @param id employee's ID
	 * @param ssn employee's SSN
	 */
	public Employee(int id, String ssn)
	{
		this.id = id;
		this.ssn = ssn;
	}
	
	/**
	 * get an employee's ID
	 * @return id
	 */
	public int getId()
	{
		return id;
	}
	
	/**
	 * get an employee's SSN
	 * @return SSN
	 */	
	public String getSsn()
	{
		return ssn;
	}
	
	/**
	 * set an employee's username when registering 
	 * @param name an empoyee's username
	 */
	public void setUsername(String name)
	{
		this.userName = name;
	}
	
	/**
	 * get an employee's username
	 * @return username
	 */
	public String getUsername()
	{
		return userName;
	}
	
	/**
	 * set the hash value of the password
	 * @param hashValue hash value of the password 
	 */
	public void setPswhash(int hashValue)
	{
		pswHash = hashValue;
	}
	
	/**
	 * get the hash value of the password
	 * @return the hash value of the password
	 */
	public int getPswhash()
	{
		return pswHash;
	}
	
	/**
	 * set the PIN
	 * @param pinNumber a 4-digit integer
	 */
	public void setPin(int pinNumber)
	{
		pin = pinNumber;
	}
	
	/**
	 * get the PIN
	 * @return the PIN
	 */
	public int getPin()
	{
		return pin;
	}
	
	/**
	 * get the whole record of an employee
	 * @return the combination of all records
	 */
	public String getRecord()
	{
		return (id + "@" + ssn + "@" + userName + "@" + pswHash + "@" + pin);
	}
}
