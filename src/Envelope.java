import java.util.ArrayList;


// modified for phase 4 not done yet
public class Envelope implements java.io.Serializable {

	/**
	 * unit to exchange data between server and client
	 */
	private static final long serialVersionUID = -7726335089122193103L;
	private String msg;
	private Integer sn;
	private ArrayList<Object> objContents = new ArrayList<Object>();
	private byte[] hmac;

	public Envelope(String text)
	{
		msg = text;
	}

	public int getSequenceNum() {
		return this.sn.intValue();
	}

	public String getMessage()
	{
		return msg;
	}

	public ArrayList<Object> getObjContents()
	{
		return objContents;
	}

	public void addObject(Object object)
	{
		objContents.add(object);
	}

	// get all the information in the envelope to form a byte array for Hmac to sign
	public byte[] getBytesToSign() {
		SecurityLib lib = SecurityLib.getInstance();
		byte[] msg_bytes = lib.objectToBytes(msg);
		byte[] sn_bytes = lib.objectToBytes(sn);
		byte[] objects_bytes = lib.objectToBytes(objContents);
		return lib.combineByteArrays(lib.combineByteArrays(msg_bytes, sn_bytes), objects_bytes);
	}

	public byte[] getHmac() {
		return this.hmac;
	}

	public void setHmac(byte[] hmac) {
		this.hmac = hmac;
	}

	public void setSequenceNum(int num) {
		this.sn = num;
	}

}
