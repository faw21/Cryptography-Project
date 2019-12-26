/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.List;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ObjectInputStream;
import java.util.ArrayList;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.io.ObjectOutputStream;


public class FileThread extends Thread
{
	private final Socket socket;
	private int messageSeqNum = 0;
	private SecurityLib lib;
	private Key integrityKey;
	private boolean proceed = true;

	public FileThread(Socket _socket)
	{
		socket = _socket;
	}

	private byte[] doDiffieHellman(SecurityLib lib, InputStream input, OutputStream output) {
		// generate key pair and prepare public key deCipher
		KeyPair keyPair = lib.generateKeyPairDH();
		byte[] pubCode = keyPair.getPublic().getEncoded();
		PrivateKey privateKey = lib.readPrivateKeyFromFile("file_private.key");
		Cipher deCipher = lib.getPublicKeyDeCipher(privateKey);

		// decrypt user public key for dh and generate symmetric key
		byte[] encryptedClientPubKeyCode = (byte[])lib.readObject(input);
		System.out.println("Client public read");
		byte[] clientPubKeyCode = lib.decrypt(encryptedClientPubKeyCode, deCipher);
		byte[] sharedSecret = lib.getSharedSecret(keyPair, clientPubKeyCode);
		// Key key = lib.getSymmetricKeyFromBytes(sharedSecret);
		System.out.println("Symmetric key generated");

		// send signed public key to user
		Envelope keyEnvelope = new Envelope("dh key");
		keyEnvelope.addObject(pubCode);
		keyEnvelope.addObject(lib.sign(pubCode, privateKey));
		lib.writeObject(keyEnvelope, output);
		System.out.println("Server public key written");
		System.out.println("Server signature written");
		System.out.println("Secure Connection generated!!!");
		
		// return key;
		return sharedSecret;

	}

	// show error message to the client about the signature error of the token
	private void tokenSignatureError(OutputStream output, Cipher enCipher) {
		Envelope e = new Envelope("TOKEN-SIGNATURE-ERROR");
		e.setSequenceNum(messageSeqNum++);
		lib.signEnvelope(e, integrityKey);
		// SecurityLib lib = SecurityLib.getInstance();
		lib.writeEncryptedObject(e, output, enCipher);
	}

	// show error message to the client about the wrong file server of the token
	private void wrongFileServerError(OutputStream output, Cipher enCipher) {
		Envelope e = new Envelope("WRONG-FILE-SERVER-ERROR");
		e.setSequenceNum(messageSeqNum++);
		lib.signEnvelope(e, integrityKey);
		// SecurityLib lib = SecurityLib.getInstance();
		lib.writeEncryptedObject(e, output, enCipher);
	}

	private boolean verifyEnvelope(Envelope e) {
		int verificationResult = lib.verifyEnvelope(e, integrityKey, messageSeqNum);
		if (verificationResult < 0) {
			return false;
		} else {
			messageSeqNum = verificationResult;
			return true;
		}
	}

	public void run()
	{
		proceed = true;
		lib = SecurityLib.getInstance();
		PublicKey selfPubKey = lib.readPublicKeyFromFile("file_public.key");
		String selfPubKeyString = lib.getPublicKeyString(selfPubKey);
		try
		{
			// set the socket and I/O up
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			// final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			// final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			InputStream input = socket.getInputStream();
			OutputStream output = socket.getOutputStream();
			PublicKey groupPublicKey = lib.readPublicKeyFromFile("group_public.key");
			Envelope response; // the response to send to client

			// phase 4
			// diffie hellman to get the symmetric key, and IV, derive the cipher key and integrity key from DH shared secret
			byte[] secret = doDiffieHellman(lib, input, output);
			Key symmetricKey = lib.getSymmetricKeyForCipher(secret);
			integrityKey = lib.getSymmetricKeyForHMAC(secret);
			
			// Key symmetricKey = doDiffieHellman(lib, input, output);
			byte[] ivMaterial = (byte[]) lib.readObject(input);
			IvParameterSpec iv = new IvParameterSpec(ivMaterial);

			if (symmetricKey == null || iv == null) {
				System.out.println("broken protocol");
				return;
			}

			Cipher enCipher = lib.getSymmetricEnCipher(symmetricKey, iv);
			Cipher deCipher = lib.getSymmetricDeCipher(symmetricKey, iv);
			byte[] challenge = lib.generateChallenge();
			lib.writeEncryptedObject(challenge, output, enCipher);

			byte[] challengeResponse = (byte[]) lib.readEncryptedObject(input, deCipher);
			if (!lib.verifyChallenge(challenge, challengeResponse)) {
				System.out.println("challenge failed");
				return;
			}

			do
			{
				// read the input as an envelope, the message is the operation to do
				Envelope e = (Envelope)lib.readEncryptedObject(input, deCipher);
				if (!verifyEnvelope(e)){
					return;
				}
				System.out.println("Request received: " + e.getMessage());

				// Handler to list files that this user is allowed to see
				if(e.getMessage().equals("LFILES"))
				{
					// e.getObject().get(0) will be the token
					// if the request is successful, the message should be "OK", and the first object of the response should be a list of strings(of file names)
					UserToken token = (UserToken) e.getObjContents().get(0);
					if (!lib.verifyToken(token, groupPublicKey)) {
						tokenSignatureError(output, enCipher);
						break;
					}
					if (!((SimpleToken)token).getFilePubKey().equals(selfPubKeyString)) {
						wrongFileServerError(output, enCipher);
						break;
					}

					List<String> groups = token.getGroups();
					ArrayList<ShareFile> allFiles = FileServer.fileList.getFiles();  //get all files information from the FileList
					List<String> userFiles = new ArrayList<String>(); // declare the list for returning files that the user can see
					for (ShareFile file : allFiles) {
						String fileName = file.getPath();
						String fileGroup = file.getGroup();
						for (String userGroup : groups) {
							if (userGroup.equals(fileGroup)) {
								userFiles.add(fileName);
							}
						}
					}
					response = new Envelope("OK");
					response.setSequenceNum(messageSeqNum++);
					response.addObject(userFiles);
					lib.signEnvelope(response, integrityKey);
					lib.writeEncryptedObject(response, output, enCipher);
				}
				if(e.getMessage().equals("UPLOADF")) // the operation is upload file
				{

					if(e.getObjContents().size() < 3) // upload file need at least 3 objects in the envelop
					{
						response = new Envelope("FAIL-BADCONTENTS");
						response.setSequenceNum(messageSeqNum++);
					}
					else
					{
						if(e.getObjContents().get(0) == null) { // the first object is the path
							response = new Envelope("FAIL-BADPATH");
							response.setSequenceNum(messageSeqNum++);
						}
						if(e.getObjContents().get(1) == null) { // the second object is the group
							response = new Envelope("FAIL-BADGROUP");
							response.setSequenceNum(messageSeqNum++);
						}
						if(e.getObjContents().get(2) == null) { // the third object is the token
							response = new Envelope("FAIL-BADTOKEN");
							response.setSequenceNum(messageSeqNum++);
						}
						else {
							String remotePath = (String)e.getObjContents().get(0);
							String group = (String)e.getObjContents().get(1);
							UserToken yourToken = (UserToken)e.getObjContents().get(2); //Extract token
							// TODO verify token
							if (!lib.verifyToken(yourToken, groupPublicKey)) {
								tokenSignatureError(output, enCipher);
								break;
							}
							if (!((SimpleToken)yourToken).getFilePubKey().equals(selfPubKeyString)) {
								wrongFileServerError(output, enCipher);
								break;
							}

							if (FileServer.fileList.checkFile(remotePath)) { // if file exists already, return failure message
								System.out.printf("Error: file already exists at %s\n", remotePath);
								response = new Envelope("FAIL-FILEEXISTS"); //Success
								response.setSequenceNum(messageSeqNum++);
							}
							else if (!yourToken.getGroups().contains(group)) { // if the token doesn't contain the authority to access that group, return failure message
								System.out.printf("Error: user missing valid token for group %s\n", group);
								response = new Envelope("FAIL-UNAUTHORIZED"); //Success
								response.setSequenceNum(messageSeqNum++);
							}
							else  { // uploading the file
								File file = new File("shared_files/"+remotePath.replace('/', '_')); // abstract file object
								file.createNewFile(); // create the file in the directory
								FileOutputStream fos = new FileOutputStream(file);
								System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

								// TODO: test new steps to store plaintext about key info and group name
								response = new Envelope("READY FOR FILE HEADER");
								response.setSequenceNum(messageSeqNum++);
								lib.signEnvelope(response, integrityKey);
								lib.writeEncryptedObject(response, output, enCipher);

								e = (Envelope)lib.readEncryptedObject(input, deCipher);
								if (!verifyEnvelope(e)){
									return;
								}
								if (e.getMessage().equals("FILE HEADER")) {
									System.out.println("Received file header");
									byte[] keyInfo = (byte[])e.getObjContents().get(0);
									String groupName = (String)e.getObjContents().get(1);
									byte[] ivBytes = (byte[])e.getObjContents().get(2);
									ObjectOutputStream oos = new ObjectOutputStream(fos);
									oos.writeObject(keyInfo);
									oos.writeObject(groupName);
									oos.writeObject(ivBytes);
								} else {
									response = new Envelope("ERROR READING FILE HEADER");
									response.setSequenceNum(messageSeqNum++);
									lib.signEnvelope(response, integrityKey);
									lib.writeEncryptedObject(response, output, enCipher);
									continue; // TODO: not sure if the logic here is correct
								}
								// end new step

								response = new Envelope("READY"); //Success
								response.setSequenceNum(messageSeqNum++);
								lib.signEnvelope(response, integrityKey);
								lib.writeEncryptedObject(response, output, enCipher);

								e = (Envelope)lib.readEncryptedObject(input, deCipher);
								if (!verifyEnvelope(e)){
									return;
								}

								while (e.getMessage().compareTo("CHUNK")==0) { // if the envelop contains part of the file
									fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1)); // write the file to share_files directory
									response = new Envelope("READY"); //Success
									response.setSequenceNum(messageSeqNum++);
									lib.signEnvelope(response, integrityKey);
									lib.writeEncryptedObject(response, output, enCipher);
									e = (Envelope)lib.readEncryptedObject(input, deCipher);
									if (!verifyEnvelope(e)){
										return;
									}
								}

								if(e.getMessage().compareTo("EOF")==0) { // the file transfer is finished
									System.out.printf("Transfer successful file %s\n", remotePath);
									FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath); // add the new file to the group
									response = new Envelope("OK"); //Success
									response.setSequenceNum(messageSeqNum++);
								}
								else { // if the given envelop is not CHUNK, and not EOF, then something is wrong
									System.out.printf("Error reading file %s from client\n", remotePath);
									response = new Envelope("ERROR-TRANSFER"); //Success
									response.setSequenceNum(messageSeqNum++);
									// if error happens, the already transferred part is in the physical folder but not in the filelist, so from the system view, it doesn't exist
								}
								fos.close();
							}
						}
					}

					lib.signEnvelope(response, integrityKey);
					lib.writeEncryptedObject(response, output, enCipher);
				}
				else if (e.getMessage().compareTo("DOWNLOADF")==0) {

					String remotePath = (String)e.getObjContents().get(0);
					UserToken t = (UserToken)e.getObjContents().get(1);
					// TODO verify token
					if (!lib.verifyToken(t, groupPublicKey)) {
						tokenSignatureError(output, enCipher);
						break;
					}
					if (!((SimpleToken)t).getFilePubKey().equals(selfPubKeyString)) {
						wrongFileServerError(output, enCipher);
						break;
					}
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_FILEMISSING");
						e.setSequenceNum(messageSeqNum++);
						lib.signEnvelope(e, integrityKey);
						lib.writeEncryptedObject(e, output, enCipher);

					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
						e.setSequenceNum(messageSeqNum++);
						lib.signEnvelope(e, integrityKey);
						lib.writeEncryptedObject(e, output, enCipher);
					}
					else {

						try
						{
							File f = new File("shared_files/_"+remotePath.replace('/', '_'));
						if (!f.exists()) {
							System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
							e = new Envelope("ERROR_NOTONDISK");
							e.setSequenceNum(messageSeqNum++);
							lib.signEnvelope(e, integrityKey);
							lib.writeEncryptedObject(e, output, enCipher);
						}
						else {
							FileInputStream fis = new FileInputStream(f);
							ObjectInputStream ois = new ObjectInputStream(fis);

							// steps to pass the header of the file to client
							e = new Envelope("FILE HEADER");
							e.setSequenceNum(messageSeqNum++);
							e.addObject(ois.readObject());
							e.addObject(ois.readObject());
							e.addObject(ois.readObject());
							lib.signEnvelope(e, integrityKey);
							lib.writeEncryptedObject(e, output, enCipher);
							e = (Envelope)lib.readEncryptedObject(input, deCipher);
							if (!verifyEnvelope(e)){
								return;
							}
							// end step


							do {
								byte[] buf = new byte[4096];
								if (e.getMessage().compareTo("DOWNLOADF")!=0) {
									System.out.printf("Server error: %s\n", e.getMessage());
									break;
								}
								e = new Envelope("CHUNK");
								e.setSequenceNum(messageSeqNum++);
								int n = fis.read(buf); //can throw an IOException
								if (n > 0) {
									System.out.printf(".");
								} else if (n < 0) {
									System.out.println("Read error");

								}


								e.addObject(buf);
								e.addObject(new Integer(n));

								lib.signEnvelope(e, integrityKey);
								lib.writeEncryptedObject(e, output, enCipher);

								e = (Envelope)lib.readEncryptedObject(input, deCipher);
								if (!verifyEnvelope(e)){
									return;
								}


							}
							while (fis.available()>0);

							//If server indicates success, return the member list
							if(e.getMessage().compareTo("DOWNLOADF")==0)
							{

								e = new Envelope("EOF");
								e.setSequenceNum(messageSeqNum++);
								lib.signEnvelope(e, integrityKey);
								lib.writeEncryptedObject(e, output, enCipher);

								e = (Envelope)lib.readEncryptedObject(input, deCipher);
								if (!verifyEnvelope(e)){
									return;
								}
								if(e.getMessage().compareTo("OK")==0) {
									System.out.printf("File data upload successful\n");
								}
								else {

									System.out.printf("Upload failed: %s\n", e.getMessage());

								}

							}
							else {

								System.out.printf("Upload failed: %s\n", e.getMessage());

							}
						}
						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e.getMessage());
							e1.printStackTrace(System.err);

						}
					}
				}
				else if (e.getMessage().compareTo("DELETEF")==0) {

					String remotePath = (String)e.getObjContents().get(0);
					UserToken t = (UserToken)e.getObjContents().get(1);
					if (!lib.verifyToken(t, groupPublicKey)) {
						tokenSignatureError(output, enCipher);
						break;
					}
					SimpleToken sToken = (SimpleToken)t;
					if (!sToken.getFilePubKey().equals(selfPubKeyString)) {
						wrongFileServerError(output, enCipher);
						break;
					}
					// TODO verify token
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_DOESNTEXIST");
						e.setSequenceNum(messageSeqNum++);
					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
						e.setSequenceNum(messageSeqNum++);
					}
					else {

						try
						{


							File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_FILEMISSING");
								e.setSequenceNum(messageSeqNum++);
							}
							else if (f.delete()) {
								System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
								FileServer.fileList.removeFile("/"+remotePath);
								e = new Envelope("OK");
								e.setSequenceNum(messageSeqNum++);
							}
							else {
								System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_DELETE");
								e.setSequenceNum(messageSeqNum++);
							}


						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e1.getMessage());
							e1.printStackTrace(System.err);
							e = new Envelope(e1.getMessage());
							e.setSequenceNum(messageSeqNum++);
						}
					}
					lib.signEnvelope(e, integrityKey);
					lib.writeEncryptedObject(e, output, enCipher);

				}
				else if(e.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

}
