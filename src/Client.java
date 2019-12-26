import java.net.Socket;
import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.Cipher;
import java.security.Key;

public abstract class Client {

	/* protected keyword is like private but subclasses have access
	 * Socket and input/output streams
	 */
	protected Socket sock;
	protected OutputStream outStream;
	protected InputStream inStream;
	protected Cipher enCipher; // Cipher used for encrypting
	protected Cipher deCipher; // Cipher used for decrypting
	protected SecurityLib lib; 
	protected Key integrityKey; // Key used to verify integrity of messages
	protected int sequenceNum; // Counter used to verify order of messages

	public boolean connect(final String server, final int port) {
		this.lib = SecurityLib.getInstance();
		System.out.println("attempting to connect");

		try{
			// connect to the specific server
			sock = new Socket(server, port);
			System.out.println("Connected to " + server + " on port " + port);

			outStream = sock.getOutputStream();
			inStream = sock.getInputStream();

			return init();

		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}

	}

	public boolean isConnected() {
		if (sock == null || !sock.isConnected()) {
			return false;
		}
		else {
			return true;
		}
	}

	// let subclasses to override the init() method to build the security channel to servers
	public boolean init() {
		return true;
	}

	//This method has been overridden by its subclasses.
	public void disconnect() {}
}
