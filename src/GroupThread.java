/* 
This thread does all the work. It communicates with the client through Envelopes.
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;

import java.security.Key;
import java.security.KeyPair;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;

public class GroupThread extends Thread
{
	private final Socket socket;
	private GroupServer my_gs;
	private SecurityLib lib = SecurityLib.getInstance();
	private Cipher enCipher = null;
	private Cipher deCipher = null;
	private PublicKey publicKey = lib.readPublicKeyFromFile("group_public.key");
	private LogService log;
	private Key integrityKey;
	private int expectedSeqNum = 0;

	public GroupThread(Socket _socket, GroupServer _gs, LogService _l)
	{
		socket = _socket;
		my_gs = _gs;
		log = _l;
	}

	public void run()
	{
		boolean proceed = true;

		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			InputStream input = socket.getInputStream();
			OutputStream output = socket.getOutputStream();

			log.addLog(LocalDateTime.now(), "Server", "IP CONNECT: " + socket.getInetAddress() + " " + socket.getPort());
		
			//generate Diffie-Hellman keypair
			KeyPair keyPair = lib.generateKeyPairDH();
      		byte[] pubCode = keyPair.getPublic().getEncoded();  //get public key(g^s mod p)

      		byte[] ivMaterial = lib.getIVBytes(); //generate a random iv material
			IvParameterSpec iv = new IvParameterSpec(ivMaterial);

			lib.writeObject(ivMaterial, output);  //send iv material to client

			//read username from client
			String tknSubName = (String) lib.readObject(input);

			//get password key from userlist
			Key passwordKey = null;
			if(my_gs.userList.checkUser(tknSubName)) {
				passwordKey = my_gs.userList.getUserKey(tknSubName);
			}
			else {
				log.addLog(LocalDateTime.now(), "Server", "LOGIN Attempt: FAILED for nonexistent user " + tknSubName);
				throw new Exception("no user found");
			}
			//initialize cipher using password key as symmetric key
			enCipher = lib.getSymmetricEnCipher(passwordKey, iv);
      		deCipher = lib.getSymmetricDeCipher(passwordKey, iv);

      		//send group server's public key of DH
    		//(g^s mod p)
      		lib.writeEncryptedObject(pubCode, output, enCipher);

      		//get client's public (g^c mod p)
      		byte[] userPubCode = (byte[]) lib.readEncryptedObject(input, deCipher);
      		
      		//generate challenge, send it and get response
      		byte[] challenge = lib.generateChallenge();
      		lib.writeEncryptedObject(challenge, output, enCipher);

      		byte[] challengeResponse = (byte[]) lib.readEncryptedObject(input, deCipher);
      		
      		Envelope env = null;
      		//verify challenge
      		if (!lib.verifyChallenge(challenge, challengeResponse)) {
				log.addLog(LocalDateTime.now(), "Server", "LOGIN Attempt: FAILED for user " + tknSubName);
				System.out.println("challenge failed");
				env = new Envelope("PASSWORDFAIL");
				lib.writeObject(env, output);
				return;
			}
			else System.out.println("Success!");

			//generate symmetrickey
      		byte[] sharedSecret = lib.getSharedSecret(keyPair, userPubCode);
			Key symmetricKey = lib.getSymmetricKeyForCipher(sharedSecret);
			integrityKey = lib.getSymmetricKeyForHMAC(sharedSecret);

      		//generate new random iv
      		ivMaterial = lib.getIVBytes();
			iv = new IvParameterSpec(ivMaterial);

			//send iv
			env = new Envelope("IV");
			env.addObject(ivMaterial);
			lib.writeObject(env, output);

			//re-initialize cipher using symmetrickey and iv
			enCipher = lib.getSymmetricEnCipher(symmetricKey, iv);
      		deCipher = lib.getSymmetricDeCipher(symmetricKey, iv);

			do
			{
				Envelope message = (Envelope)lib.readEncryptedObject(input, deCipher);
				if(!verifyEnvelope(message)) {
					log.addLog(LocalDateTime.now(), "Server", 
					"ERROR - Envelope verification FAILED expectedSeq: " + expectedSeqNum + " receivedSeq: " + message.getSequenceNum());
					return;
				}

				System.out.println("Request received: " + message.getMessage());

				Envelope response;
				log.addLog(LocalDateTime.now(), tknSubName, "Request for :" + message.getMessage());

				if(message.getMessage().equals("GET"))//Client wants a token
				{
					//String username = (String)message.getObjContents().get(0); //Get the username
					if(tknSubName == null)
					{
						sendFailure("Username was NULL", output);
					}
					else
					{
						String fileServId = (String)message.getObjContents().get(0);
						SimpleToken yourToken = (SimpleToken)createToken(tknSubName, fileServId); //Create a token

						//Respond to the client. On error, the client will receive a null token
						response = new Envelope("OK");

						PrivateKey privateKey = lib.readPrivateKeyFromFile("group_private.key");
						lib.signToken(yourToken, privateKey);
						response.addObject(yourToken);

						sendEnvelope(response, "SUCCESS - Sent Token for " + tknSubName, tknSubName, output);
					}
				}
				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
				{
					if(message.getObjContents().size() < 3)
					{
						sendFailure("Bad Request - insufficient contents in request", output);
					}
					else
					{
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null && message.getObjContents().get(2) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								Key passKey = (Key)message.getObjContents().get(1); //Extract the new user's password key
								UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the token

								if(createUser(username, passKey, yourToken))
								{
									sendEnvelope(new Envelope("OK"), "SUCCESS - Created user " + username, tknSubName, output);

								} else sendFailure("Internal Error - unable to create user", output);
							} else sendFailure("Bad Request - invalid contents in request", output);
						}else sendFailure("Bad Request - invalid contents in request", output);
					}					
				}
				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{

					if(message.getObjContents().size() < 2)
					{
						sendFailure("Bad Request - insufficient contents in request", output);
					}
					else
					{
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

								if(deleteUser(username, yourToken))
								{
									sendEnvelope(new Envelope("OK"), "SUCCESS - Deleted User " + username, yourToken.getSubject(), output);

								} else sendFailure("Bad Request - user delete failed", output);
							} else sendFailure("Bad Request - invalid contents in request", output);
						} else sendFailure("Bad Request - insufficient contents in request", output);
					}					
				}
				else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
				{
						if(message.getObjContents().size() == 2)
						{
							if(message.getObjContents().get(0) != null)
							{
								if(message.getObjContents().get(1) != null)
								{
									String groupName = (String)message.getObjContents().get(0); //Extract the username
									UserToken token = (UserToken)message.getObjContents().get(1); //Extract the token
									
									UserList ul = my_gs.userList;
									GroupList gl = my_gs.groupList;

									if(lib.verifyToken(token, publicKey))
									{
										//Group must not already exist, attempt to add the group
										if(!gl.checkGroup(groupName) && gl.addGroup(groupName, token.getSubject()))
										{
											ul.addOwnership(token.getSubject(), groupName);
											gl.addMember(token.getSubject(), groupName);

											//Create a re-openable file of to keep track of the group key
											GroupKeyManager gkm = new GroupKeyManager();
											
											FileOutputStream f = new FileOutputStream(new File(groupName+"_GK.gkm"));
											ObjectOutputStream o = new ObjectOutputStream(f);

											o.writeObject(gkm);

											f.close();
											o.close();

											sendEnvelope(new Envelope("OK"), "SUCCESS - Created Group " + groupName, tknSubName, output);
										}
										else
										{
											sendFailure("Group DNE or Failed to add Group " + groupName, output);
										}
									}
									else
									{
										System.out.println("Token has been compromised. Request Denied.");
										sendFailure("Failed to Verify Token", output);
									}
								}
							}
						}
						else
						{
							sendFailure("Message contents were not complete", output);
						}
				}
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
					if(message.getObjContents().size() == 2 &&
					message.getObjContents().get(0) != null &&
					message.getObjContents().get(1) != null)
					{
						GroupList gl = my_gs.groupList;
						String groupName = (String)message.getObjContents().get(0);
						if(groupName.equals("ADMIN") || !gl.checkGroup(groupName)) //Cannot delete admin group // group must exist
						{

							sendFailure("Group " + groupName + " DNE", output);
						}
						else
						{

							UserToken token = (UserToken)message.getObjContents().get(1);
							
							if(!lib.verifyToken(token, publicKey)){
								System.out.println("Token has been compromised. Request Denied.");
								sendFailure("Failed to Verify Token for " + tknSubName, output);
							}
							String owner = gl.getGroupOwner(groupName);

							if(owner.equals((String)token.getSubject()))
							{
								ArrayList<String> gmembers = gl.getGroupMembers(groupName);
								UserList ul = my_gs.userList;

								//Remove the group from user's
								for(String member : gmembers)
								{
									ul.removeGroup(member, groupName);
								}
								ul.removeOwnership(token.getSubject(), groupName);

								//Remove the grouplist
								gl.deleteGroup(groupName);

								//Remove the groupkey
								File gkmFile = new File(groupName + "_GK.gkm");
								gkmFile.delete();

								sendEnvelope(new Envelope("OK"), "SUCCESS Deleted Group " + groupName, token.getSubject(), output);
							}
							else
							{
								sendFailure(tknSubName + " attmpted to delete group " + groupName, output);
							}
						}
					}
					else
					{
						//Message didn't have required contents
						sendFailure("Bad request - insufficient request contents", output);
					}

				}
				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{

					if(message.getObjContents().size() == 2)
					{

						String groupName = (String)message.getObjContents().get(0);
						UserToken token = (UserToken)message.getObjContents().get(1);
						GroupList gl = my_gs.groupList;

						if(groupName == null || token == null) {
							sendFailure("Bad request - insufficient request contents", output);
						}
						if(!lib.verifyToken(token, publicKey)){
							System.out.println("Token has been compromised. Request Denied.");
							sendFailure("Failed to Verify Token", output);
						}

						if(gl.checkGroup(groupName)){

							String owner = gl.getGroupOwner(groupName);

							//Verify user is the owner via group list
							if(owner.equals((String)token.getSubject()))
							{
								//Send data in object(0)
								response = new Envelope("OK");
								response.addObject(gl.getGroupMembers(groupName));

								sendEnvelope(response, "SUCCESS - List Members of " + groupName, token.getSubject(), output);
							}
							else
							{
								sendFailure(tknSubName + " attempted to list members of " + groupName, output);
							}

						}
						else
						{
							sendFailure(tknSubName + " attempted to list nonexistent group " + groupName, output);
						}

					}
					else
					{
						sendFailure("Bad request - insufficient request contents", output);
					}

				}
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
					if(message.getObjContents().size() == 3)
					{
						String user = (String)message.getObjContents().get(0);
						String groupName = (String)message.getObjContents().get(1);
						UserToken token = (UserToken)message.getObjContents().get(2);
						GroupList gl = my_gs.groupList;
						UserList ul = my_gs.userList;
						if(!lib.verifyToken(token, publicKey)){
							System.out.println("Token has been compromised. Request Denied.");
							sendFailure("Failed to Verify Token", output);
						}

						if(user != null && groupName != null && token != null && gl.checkGroup(groupName) && ul.checkUser(user) )
						{
							
							String owner = gl.getGroupOwner(groupName);

							//Verify user is the owner via group list
							if(owner.equals((String)token.getSubject())
								&& !ul.getUserGroups(user).contains(groupName)
								&& !(gl.getGroupMembers(groupName).contains(user)))
							{

								gl.addMember(user, groupName);
								ul.addGroup(user, groupName);

								sendEnvelope(new Envelope("OK"), "SUCCESS - Add " + user + " to " + groupName, tknSubName, output);
							}
							else sendFailure("Must be owner of an existing group and " + user+ " must not already be part of that group" , output);
						}
						else
						{
							sendFailure("Bad request - user/group either DNE or was empty from " + tknSubName, output);
						}

					}
					else
					{
						sendFailure("Bad request - insufficient request contents", output);
					}

				}
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
					if(message.getObjContents().size() == 3)
					{
						String user = (String)message.getObjContents().get(0);
						String groupName = (String)message.getObjContents().get(1);
						UserToken token = (UserToken)message.getObjContents().get(2);
						GroupList gl = my_gs.groupList;
						UserList ul = my_gs.userList;
						if(!lib.verifyToken(token, publicKey)){
							System.out.println("Token has been compromised. Request Denied.");
							sendFailure("Failed to Verify Token", output);
						}

						if(user == null || groupName == null || token == null) {
							sendFailure("Request contents were null", output);
						}

						if(gl.checkGroup(groupName) && 
						ul.checkUser(user) &&
						gl.getGroupMembers(groupName).contains(user))
						{
							String owner = gl.getGroupOwner(groupName);

							//Verify user is the owner via group list
							if(owner.equals((String)token.getSubject()))
							{
								gl.removeMember(user, groupName);
								ul.removeGroup(user,groupName);

								//Update the key and keyfile
								FileInputStream fi = new FileInputStream(new File(groupName + "_GK.gkm"));
								ObjectInputStream oi = new ObjectInputStream(fi);
								GroupKeyManager gkm = (GroupKeyManager) oi.readObject();
								oi.close();
								fi.close();

								gkm.changeKey();

								FileOutputStream fo = new FileOutputStream(new File(groupName + "_GK.gkm"));
								ObjectOutputStream os = new ObjectOutputStream(fo);
								os.writeObject(gkm);
								fo.close();
								os.close();


								sendEnvelope(new Envelope("OK"), "SUCCESS - Removed " + user + " from group " + groupName, tknSubName, output);
							}
							else
							{
								sendFailure(tknSubName + " attempted to remove " + user + " from group " + groupName  + " which they are not the owner of ", output);
							}
						}
						else
						{
							sendFailure(tknSubName + " attempted to access group " + groupName + " to remove " + user + " resulting in DNE ", output);
						}

					}
					else
					{
						sendFailure("Bad request - insufficient request contents", output);
					}
				}
				else if(message.getMessage().equals("CHANGEP")) //Client wants to delete a user
				{

					if(message.getObjContents().size() < 2)
					{
						sendFailure("Bad request - insufficient request contents", output);
					}
					else
					{
						Key passKey = (Key)message.getObjContents().get(0);
						UserToken token = (UserToken)message.getObjContents().get(1);
						if(!lib.verifyToken(token, publicKey)){
							System.out.println("Token has been compromised. Request Denied.");
							sendFailure("Failed to Verify Token", output);
						}

						if(my_gs.userList.checkUser(token.getSubject())){
							if(my_gs.userList.getUserKey((String)token.getSubject())!=passKey){

								my_gs.userList.setUserKey((String)token.getSubject(), passKey);

								sendEnvelope(new Envelope("OK"), "SUCCESS - Changed Password", tknSubName, output);
							}
							else sendFailure("Password did not match stored password for user " + tknSubName, output);
						}
						else sendFailure("User " + token.getSubject() + " DNE", output);
					}
				}
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					log.addLog(LocalDateTime.now(), tknSubName, "DISCONNECT");
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}
				else
				{
					sendFailure("Bad request - request value \"" + message.getMessage() + "\" not understood", output); //Server does not understand client request
				}
				System.out.println("Request Handled");
			}while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	//Method to create tokens
	private UserToken createToken(String username, String fileServId) throws IOException, ClassNotFoundException
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{

			//Get the group keys for the token
			HashMap<String, GroupKey> keyMap = new HashMap<String, GroupKey>();

			UserList ul = my_gs.userList;
			for(String gName : ul.getUserGroups(username)) {
				FileInputStream fi = new FileInputStream(new File(gName + "_GK.gkm"));
				ObjectInputStream oi = new ObjectInputStream(fi);
				GroupKeyManager gkm = (GroupKeyManager) oi.readObject();

				keyMap.put(gName, gkm.getGroupKey());
				oi.close();
				fi.close();
			}
			
			//Issue a new token with server's name, user's name, and user's groups
			UserToken yourToken = new SimpleToken(my_gs.name, username, my_gs.userList.getUserGroups(username), fileServId, keyMap);
			
			return yourToken;
		}
		else
		{
			return null;
		}
	}


	//Method to create a user
	private boolean createUser(String username, Key passwordKey, UserToken yourToken)
	{
		String requester = yourToken.getSubject();

		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			if(!lib.verifyToken(yourToken, publicKey))
			{
				System.out.println("Token has been compromised. Request Denied.");
				return false;
			}
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administrator
			if(temp.contains("ADMIN"))
			{
				//Does user already exist?
				if(my_gs.userList.checkUser(username))
				{
					return false; //User already exists
				}
				else
				{
					my_gs.userList.addUser(username, passwordKey);
					return true;
				}
			}
			else
			{
				return false; //requester not an administrator
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	//Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();

		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			if(!lib.verifyToken(yourToken, publicKey))
			{
				System.out.println("Token has been compromised. Request Denied.");
				return false;
			}

			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administer
			if(temp.contains("ADMIN"))
			{
				//Does user exist?
				if(my_gs.userList.checkUser(username))
				{
					//User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<String>();

					//This will produce a hard copy of the list of groups this user belongs
					for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++)
					{
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
					}

					//Delete the user from the groups
					//If user is the owner, removeMember will automatically delete group!
					for(int index = 0; index < deleteFromGroups.size(); index++)
					{
						my_gs.groupList.removeMember(username, deleteFromGroups.get(index));
					}

					//If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();

					//Make a hard copy of the user's ownership list
					for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++)
					{
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}

					//Delete owned groups
					for(int index = 0; index < deleteOwnedGroup.size(); index++)
					{
						//Use the delete group method. Token must be created for this action
						deleteGroup(deleteOwnedGroup.get(index), new SimpleToken(my_gs.name, username, deleteOwnedGroup));
					}

					//Delete the user from the user list
					my_gs.userList.deleteUser(username);

					return true;
				}
				else
				{
					return false; //User does not exist

				}
			}
			else
			{
				return false; //requester is not an administer
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	private boolean deleteGroup(String groupName, UserToken token)
	{
		GroupList groupList = my_gs.groupList;
		UserList userList = my_gs.userList;

		List<String> subjectGroups = token.getGroups();
		String subject = token.getSubject();
		//Permission check - Must be group owner or ADMIN
		if(!subject.equals(groupList.getGroupOwner(groupName)) && !(subjectGroups.contains("ADMIN")))
		{
			return false;
		}

		ArrayList<String> members = groupList.getGroupMembers(groupName);
		for(String user : members)
		{
			userList.removeGroup(user, groupName);
		}

		groupList.deleteGroup(groupName);
		return true;
	}

	//short helper
	//@param errMsg - Include an optional error message for a more detailed
	//	description of why it failed
	private void sendFailure(String errMsg, OutputStream output)
	{
		try
		{
			Envelope response = new Envelope("FAIL");
			if(errMsg != null) {response.addObject(errMsg);}
			response.setSequenceNum(expectedSeqNum++);
			lib.signEnvelope(response, integrityKey);
			lib.writeEncryptedObject(response, output, enCipher);
			log.addLog(LocalDateTime.now(), "SERVER", "FAIL - Failure caused by - " + (errMsg != null? errMsg : "UKN"));
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		System.out.println("Request resulted in Failure. " + errMsg); //TODO include errMsg
	}

	private void sendEnvelope(Envelope e, String logMsg, String usrName, OutputStream output) throws IOException {
		e.setSequenceNum(expectedSeqNum++);
		lib.signEnvelope(e, integrityKey);
		lib.writeEncryptedObject(e, output, enCipher);
		log.addLog(LocalDateTime.now(), usrName, logMsg);
	}

	private boolean verifyEnvelope(Envelope e) {
		int verificationResult = lib.verifyEnvelope(e, integrityKey, expectedSeqNum);
		if (verificationResult < 0) {
			return false;
		} else {
			expectedSeqNum++;
			return true;
		}
	}
}
