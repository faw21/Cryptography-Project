
/* Implements the GroupClient Interface */
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.security.Key;
import java.security.KeyPair;
import javax.crypto.spec.IvParameterSpec;
import java.security.PublicKey;

public class GroupClient extends Client implements GroupClientInterface {

	private int groupSeqNum;

	public GroupClient() {
		groupSeqNum = 0;
	}

	// override connect() in Client.java
	// takes four arguments
	public boolean connect(final String server, final int port, String username, String password) {
		this.lib = SecurityLib.getInstance();
		System.out.println("attempting to connect");

		try {
			// connect to the specific server
			sock = new Socket(server, port);
			System.out.println("Connected to " + server + " on port " + port);

			outStream = sock.getOutputStream();
			inStream = sock.getInputStream();

			// set up I/O streams with the server
			return init(username, password);

		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}

	}

	// Do the Deffie Hellman Exchange
	public boolean init(String username, String password) {

		try {

			KeyPair keyPair = lib.generateKeyPairDH(); // generate Diffie-Hellman keypair
			byte[] pubCode = keyPair.getPublic().getEncoded(); // get public key(g^c mod p)

			Key passwordKey = lib.generateKeyFromPassword(password);// generate key from the password

			byte[] ivMaterial = null;
			ivMaterial = (byte[]) lib.readObject(inStream);// get iv Material from Group Server

			IvParameterSpec iv = new IvParameterSpec(ivMaterial); // generate iv

			lib.writeObject(username, outStream); // send username to server

			// initialize enCipher and deCipher using password key as symmetric key
			this.enCipher = lib.getSymmetricEnCipher(passwordKey, iv);
			this.deCipher = lib.getSymmetricDeCipher(passwordKey, iv);

			// get group server's public key of DH
			// (g^s mod p)
			byte[] groupServerPubCode = (byte[]) lib.readEncryptedObject(inStream, this.deCipher);

			// send public key(g^c mod p) to the server
			lib.writeEncryptedObject(pubCode, outStream, this.enCipher);

			// get challenge and respond
			byte[] challenge = (byte[]) lib.readEncryptedObject(inStream, this.deCipher);
			lib.writeEncryptedObject(lib.responseChallenge(challenge), outStream, this.enCipher);

			// generate symmetric key
			byte[] sharedSecret = lib.getSharedSecret(keyPair, groupServerPubCode);
			Key symmetricKey = lib.getSymmetricKeyForCipher(sharedSecret);
			this.integrityKey = lib.getSymmetricKeyForHMAC(sharedSecret);

			Envelope response = (Envelope) lib.readObject(inStream);
			if (response.getMessage().equals("PASSWORDFAIL")) {
				System.out.println("Wrong password!");
				return false;
			}
			// get iv material again
			else
				ivMaterial = (byte[]) response.getObjContents().get(0);

			iv = new IvParameterSpec(ivMaterial);
			// use new iv and generated symmetric key to
			// re-initialize enCipher and deCipher
			this.enCipher = lib.getSymmetricEnCipher(symmetricKey, iv);
			this.deCipher = lib.getSymmetricDeCipher(symmetricKey, iv);

			return true;
		} catch (Exception e) {
			System.out.println("Wrong password");
			return false;
		}

	}

	// public UserToken getToken(String username)
	public UserToken getToken() {
		try {
			UserToken token = null;
			Envelope message = null, response = null;

			// Tell the server to return a token.
			message = new Envelope("GET");
			message.setSequenceNum(groupSeqNum++);
			PublicKey fileServerPublicKey = lib.readPublicKeyFromFile("file_public.key");
			String pubKeyString = lib.getPublicKeyString(fileServerPublicKey);
			message.addObject(pubKeyString);
			lib.signEnvelope(message, this.integrityKey);
			lib.writeEncryptedObject(message, outStream, this.enCipher);

			// Get the response from the server
			response = (Envelope) lib.readEncryptedObject(inStream, this.deCipher);
			if (lib.verifyEnvelope(response, integrityKey, groupSeqNum++) < 0) {
				disconnect();
				return null;
			}

			// Successful response
			if (response.getMessage().equals("OK")) {
				// If there is a token in the Envelope, return it
				ArrayList<Object> temp = null;
				temp = response.getObjContents();

				if (temp.size() == 1) {
					token = (UserToken) temp.get(0);
					PublicKey groupPublicKey = lib.readPublicKeyFromFile("group_public.key");
					if (lib.verifyToken(token, groupPublicKey))
						return token;
					else
						return null;
				}
			}

			return null;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	public boolean createUser(String newUsername, String newPassword, UserToken token) {
		try {
			Envelope message = null, response = null;
			// Tell the server to create a user
			message = new Envelope("CUSER");
			message.setSequenceNum(groupSeqNum++);
			message.addObject(newUsername); // Add user name string
			Key newPassKey = lib.generateKeyFromPassword(newPassword);
			message.addObject(newPassKey);
			message.addObject(token); // Add the requester's token
			lib.signEnvelope(message, this.integrityKey);
			lib.writeEncryptedObject(message, outStream, this.enCipher);

			response = (Envelope) lib.readEncryptedObject(inStream, this.deCipher);
			if (lib.verifyEnvelope(response, integrityKey, groupSeqNum++) < 0) {
				disconnect();
				return false;
			}

			// If server indicates success, return true
			// TODO: err codes for better debugging
			if (response.getMessage().equals("OK")) {
				System.out.println("User " + newUsername + " has been created.");
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean deleteUser(String username, UserToken token) {
		try {
			Envelope message = null, response = null;

			// Tell the server to delete a user
			message = new Envelope("DUSER");
			message.addObject(username); // Add user name
			message.addObject(token); // Add requester's token
			message.setSequenceNum(groupSeqNum++);
			lib.signEnvelope(message, this.integrityKey);
			lib.writeEncryptedObject(message, outStream, this.enCipher);

			response = (Envelope) lib.readEncryptedObject(inStream, this.deCipher);
			if (lib.verifyEnvelope(response, integrityKey, groupSeqNum++) < 0) {
				disconnect();
				return false;
			}

			// If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				System.out.println("User " + username + " has been deleted");
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean createGroup(String groupname, UserToken token) {
		try {
			Envelope message = null, response = null;
			// Tell the server to create a group
			message = new Envelope("CGROUP");
			message.addObject(groupname); // Add the group name string
			message.addObject(token); // Add the requestor's token
			message.setSequenceNum(groupSeqNum++);
			lib.signEnvelope(message, this.integrityKey);
			lib.writeEncryptedObject(message, outStream, this.enCipher);

			response = (Envelope) lib.readEncryptedObject(inStream, this.deCipher);
			if (lib.verifyEnvelope(response, integrityKey, groupSeqNum++) < 0) {
				disconnect();
				return false;
			}

			// If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				System.out.println("Group " + groupname + " has been created");
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean deleteGroup(String groupname, UserToken token) {
		try {
			Envelope message = null, response = null;
			// Tell the server to delete a group
			message = new Envelope("DGROUP");
			message.addObject(groupname); // Add group name string
			message.addObject(token); // Add requestor's token
			message.setSequenceNum(groupSeqNum++);
			lib.signEnvelope(message, this.integrityKey);
			lib.writeEncryptedObject(message, outStream, this.enCipher);

			response = (Envelope) lib.readEncryptedObject(inStream, this.deCipher);
			if (lib.verifyEnvelope(response, integrityKey, groupSeqNum++) < 0) {
				disconnect();
				return false;
			}
			// If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				System.out.println("Group " + groupname + " has been deleted");
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	@SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token) {
		try {
			Envelope message = null, response = null;
			// Tell the server to return the member list
			message = new Envelope("LMEMBERS");
			message.addObject(group); // Add group name string
			message.addObject(token); // Add requester's token
			message.setSequenceNum(groupSeqNum++);
			lib.signEnvelope(message, this.integrityKey);
			lib.writeEncryptedObject(message, outStream, this.enCipher);

			response = (Envelope) lib.readEncryptedObject(inStream, this.deCipher);
			if (lib.verifyEnvelope(response, integrityKey, groupSeqNum++) < 0) {
				disconnect();
				return null;
			}

			// If server indicates success, return the member list
			if (response.getMessage().equals("OK")) {
				System.out.println("List returned");
				return (List<String>) response.getObjContents().get(0); // This cast creates compiler warnings. Sorry.
			}

			return null;

		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	public boolean addUserToGroup(String username, String groupname, UserToken token) {
		try {
			Envelope message = null, response = null;
			// Tell the server to add a user to the group
			message = new Envelope("AUSERTOGROUP");
			message.addObject(username); // Add user name string
			message.addObject(groupname); // Add group name string
			message.addObject(token); // Add requester's token
			message.setSequenceNum(groupSeqNum++);
			lib.signEnvelope(message, this.integrityKey);
			lib.writeEncryptedObject(message, outStream, this.enCipher);

			response = (Envelope) lib.readEncryptedObject(inStream, this.deCipher);
			if (lib.verifyEnvelope(response, integrityKey, groupSeqNum++) < 0) {
				disconnect();
				return false;
			}

			// If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				System.out.println("User " + username + " has been added to group " + groupname);
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean deleteUserFromGroup(String username, String groupname, UserToken token) {
		try {
			Envelope message = null, response = null;
			// Tell the server to remove a user from the group
			message = new Envelope("RUSERFROMGROUP");
			message.addObject(username); // Add user name string
			message.addObject(groupname); // Add group name string
			message.addObject(token); // Add requester's token
			message.setSequenceNum(groupSeqNum++);
			lib.signEnvelope(message, this.integrityKey);
			lib.writeEncryptedObject(message, outStream, this.enCipher);

			response = (Envelope) lib.readEncryptedObject(inStream, this.deCipher);
			if (lib.verifyEnvelope(response, integrityKey, groupSeqNum++) < 0) {
				disconnect();
				return false;
			}
			// If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				System.out.println("User " + username + " has been deleted from group " + groupname);
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean changePassword(String newPassword, UserToken token) {
		try {
			Envelope message = null, response = null;
			// Tell the server to remove a user from the group
			message = new Envelope("CHANGEP");
			Key newPassKey = lib.generateKeyFromPassword(newPassword);
			message.addObject(newPassKey);
			message.addObject(token); // Add requester's token
			message.setSequenceNum(groupSeqNum++);
			lib.signEnvelope(message, this.integrityKey);
			lib.writeEncryptedObject(message, outStream, this.enCipher);

			response = (Envelope) lib.readEncryptedObject(inStream, this.deCipher);
			if (lib.verifyEnvelope(response, integrityKey, groupSeqNum++) < 0) {
				disconnect();
				return false;
			}
			// If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				System.out.println("The password of " + (String) token.getSubject() + " has been changed.");
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}
	
	//Override disconnect() in Client.java
	public void disconnect() {
		if (isConnected()) {
			try
			{
				Envelope message = new Envelope("DISCONNECT");
				message.setSequenceNum(groupSeqNum++);
				lib.signEnvelope(message, integrityKey);
				lib.writeEncryptedObject(message, outStream, enCipher);
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
}
