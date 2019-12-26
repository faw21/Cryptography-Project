/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file.
 */

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.security.Key;
import java.security.KeyPair;

public class GroupServer extends Server {

	public static final int SERVER_PORT = 8765;
	public UserList userList;
	public GroupList groupList;

	public GroupServer() {
		super(SERVER_PORT, "ALPHA");
	}

	public GroupServer(int _port) {
		super(_port, "ALPHA");
	}

	public void start() {
		// Overwrote server.start() because if no user file exists, initial admin
		// account needs to be created
		System.out.println("Starting GroupServer...");

		String userFile = "UserList.bin";
		String groupFile = "GroupList.bin";
		String publicKeyFilename = "group_public.key";
		String privateKeyFilename = "group_private.key";
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;

		// This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));

		try {
			FileInputStream pubkis = new FileInputStream(publicKeyFilename);
			FileInputStream prikis = new FileInputStream(privateKeyFilename);
			pubkis.close();
			prikis.close();
		} catch (FileNotFoundException e) {
			System.out.println("Keys do not exist, creating key pair...");
			SecurityLib lib = SecurityLib.getInstance();
			KeyPair keyPair = lib.generateKeyPair();
			lib.writeKeyToFile(keyPair.getPublic(), publicKeyFilename);
			lib.writeKeyToFile(keyPair.getPrivate(), privateKeyFilename);
		} catch (IOException e) {
			System.out.println("Can't close file input streams");
		}
		// Open user file to get user list
		try {
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList) userStream.readObject();

			fis = new FileInputStream(groupFile);
			groupStream = new ObjectInputStream(fis);
			groupList = (GroupList) groupStream.readObject();

		} catch (FileNotFoundException e) {
			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			String username = console.next();

			System.out.print("Enter your password: ");
			String password = console.next();

			while (password == null || password.length() < 8) {
				System.out.print("Enter your password (minimum length 8): ");
				password = console.next();
			}

			SecurityLib lib = SecurityLib.getInstance();
			Key passwordKey = lib.generateKeyFromPassword(password);
			byte[] code = passwordKey.getEncoded();
			for (int i = 0; i < code.length; i++) {
				System.out.print(code[i] + ":");
			}

			// Create a new lists, add current user to the ADMIN group. They now own the
			// ADMIN group.
			userList = new UserList();
			groupList = new GroupList();
			userList.addUser(username, passwordKey);
			groupList.addGroup("ADMIN", username);
			groupList.addMember(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");
			System.out.println("Created user: " + username + " in group ADMIN");

			GroupKeyManager gkm = new GroupKeyManager();

			try {
				FileOutputStream f;
				f = new FileOutputStream(new File("ADMIN_GK.gkm"));
				ObjectOutputStream o;
				o = new ObjectOutputStream(f);
				o.writeObject(gkm);
				f.close();
				o.close();
			} catch (IOException e1) {
				e1.printStackTrace();
			}

		}
		catch(IOException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}

		System.out.println("Opening Server for Connections...");

		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();

		//This block listens for connections and creates threads on new connections
		try
		{

			final ServerSocket serverSock = new ServerSocket(port);
			LogService log = new LogService();

			Socket sock = null;
			GroupThread thread = null;

			while(true)
			{
				sock = serverSock.accept();
				thread = new GroupThread(sock, this, log);
				thread.start();
			}
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}

	}

}

//This thread saves the user list
class ShutDownListener extends Thread
{
	public GroupServer my_gs;

	public ShutDownListener (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);
			outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
			outStream.writeObject(my_gs.groupList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSave extends Thread
{
	public GroupServer my_gs;

	public AutoSave (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave group and user lists...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					outStream.writeObject(my_gs.userList);
					outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
					outStream.writeObject(my_gs.groupList);
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}

			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		} while(true);
	}
}
