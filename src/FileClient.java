/* FileClient provides all the client functionality regarding the file server */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.util.List;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.util.HashMap;
import java.util.Arrays;


public class FileClient extends Client implements FileClientInterface {

	private HashMap<String, GroupKey> keyMap;

	public FileClient() {
		this.sequenceNum = 0;
	}

	public void processToken(UserToken token) {
		SimpleToken sToken = (SimpleToken) token;
		if (sToken.getGroupKeys() != null) {
			keyMap = sToken.getGroupKeys();
			sToken.removeKeys();
		} else {
			System.out.println("Token processed already!");
		}
	}

	// DH on file client side
	private byte[] doDiffieHellman(InputStream input, OutputStream output) {
		KeyPair keyPair = lib.generateKeyPairDH();
		byte[] pubCode = keyPair.getPublic().getEncoded();
		PublicKey fileServerPubKey = lib.readPublicKeyFromFile("file_public.key");
		Cipher pubCipher = lib.getPublicKeyEnCipher(fileServerPubKey);
		byte[] encryptedPubCode = lib.encrypt(pubCode, pubCipher);
		lib.writeObject(encryptedPubCode, output);
		System.out.println("Client DH public key written");
		Envelope keyEnvelope = (Envelope) lib.readObject(input);
		byte[] serverPubCode = (byte[]) keyEnvelope.getObjContents().get(0);
		byte[] serverSignature = (byte[]) keyEnvelope.getObjContents().get(1);
		System.out.println("Server DH public key read");
		System.out.println("Server signature read");
		if (!lib.verify(serverPubCode, serverSignature, fileServerPubKey)) {
			System.out.println("Server signature verification failed");
			return null;
		} else {
			System.out.println("Server signature verification succeeded.");
			System.out.println("Secure connection generated!!!\n");
		}
		byte[] sharedSecret = lib.getSharedSecret(keyPair, serverPubCode);
		return sharedSecret;
		// Key key = lib.getSymmetricKeyFromBytes(sharedSecret);
		// return key;

	}

	public boolean init() {
		// Key symmetricKey = doDiffieHellman(this.originalInput, this.outStream);
		byte[] secret = doDiffieHellman(this.inStream, this.outStream);
		if (secret == null) {
			System.out.println("broken protocol");
			return false;
		}
		Key symmetricKey = lib.getSymmetricKeyForCipher(secret);
		this.integrityKey = lib.getSymmetricKeyForHMAC(secret);
		byte[] ivMaterial = lib.getIVBytes();
		IvParameterSpec iv = new IvParameterSpec(ivMaterial);
		lib.writeObject(ivMaterial, outStream); // pass the iv to the server
		this.enCipher = lib.getSymmetricEnCipher(symmetricKey, iv);
		this.deCipher = lib.getSymmetricDeCipher(symmetricKey, iv);
		byte[] challenge = (byte[]) lib.readEncryptedObject(inStream, deCipher);
		lib.writeEncryptedObject(lib.responseChallenge(challenge), outStream, enCipher);

		return true;
	}

	public boolean delete(String filename, UserToken token) {

		processToken(token);

		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}
		
		Envelope env = new Envelope("DELETEF"); //Success
		env.addObject(remotePath);
		env.addObject(token);
		env.setSequenceNum(this.sequenceNum++);
		lib.signEnvelope(env, integrityKey);
		lib.writeEncryptedObject(env, outStream, enCipher);

		env = (Envelope)lib.readEncryptedObject(inStream, deCipher);
		this.sequenceNum = lib.verifyEnvelope(env, integrityKey, this.sequenceNum);
		if (this.sequenceNum < 0) {
			return false;
		}

		if (env.getMessage().compareTo("OK")==0) {
			System.out.printf("File %s deleted successfully\n", filename);
		}
		else {
			System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
			return false;
		}

		return true;
	}

	public boolean download(String sourceFile, String destFile, UserToken token) {

		processToken(token);

		if (sourceFile.charAt(0)=='/') {
			sourceFile = sourceFile.substring(1);
		}

		File file = new File(destFile);
		try {
			if (!file.exists()) {
				file.createNewFile();
				FileOutputStream fos = new FileOutputStream(file);
				Cipher fileDeCipher;

				Envelope env = new Envelope("DOWNLOADF"); //Success
				env.addObject(sourceFile);
				env.addObject(token);
				env.setSequenceNum(this.sequenceNum++);
				lib.signEnvelope(env, integrityKey);
				lib.writeEncryptedObject(env, outStream, enCipher);

				// steps to read the header of the file (key info, group name)
				env = (Envelope)lib.readEncryptedObject(inStream, deCipher);
				this.sequenceNum = lib.verifyEnvelope(env, integrityKey, this.sequenceNum);
				if (this.sequenceNum < 0) {
					return false;
				}
				if (env.getMessage().equals("FILE HEADER")) {
					byte[] keyInfo = (byte[])env.getObjContents().get(0);
					String groupName = (String)env.getObjContents().get(1);
					byte[] ivBytes = (byte[])env.getObjContents().get(2);
					// lib.showBytes(keyInfo); // test
					// System.out.println(groupName); // test
					// lib.showBytes(ivBytes); // test
					GroupKey groupKey = keyMap.get(groupName);
					// System.out.println(groupKey); // test
					Key fileKey = lib.getFileKey(groupKey, keyInfo);
					fileDeCipher = lib.getFileDeCipher(fileKey, ivBytes);
					env = new Envelope("DOWNLOADF");
					env.setSequenceNum(this.sequenceNum++);
					lib.signEnvelope(env, integrityKey);
					lib.writeEncryptedObject(env, outStream, enCipher);
				} else {
					System.out.println("Can't get file header from server");
					return false;
				}
				// end step


				env = (Envelope)lib.readEncryptedObject(inStream, deCipher);
				this.sequenceNum = lib.verifyEnvelope(env, integrityKey, this.sequenceNum);
				if (this.sequenceNum < 0) {
					return false;
				}

				while (env.getMessage().compareTo("CHUNK")==0) {
					byte[] receivedText = (byte[])env.getObjContents().get(0);
					// byte[] cipherText = (byte[])env.getObjContents().get(0);
					int n = (Integer)(env.getObjContents().get(1));
					// System.out.println("received length: " + n);
					byte[] cipherText;
					if (n == receivedText.length) {
						cipherText = receivedText;
					} else {
						cipherText = Arrays.copyOfRange(receivedText, 0, n);
					}
					byte[] plainText = lib.decrypt(cipherText, fileDeCipher);
					// System.out.println(plainText.length);
					fos.write(plainText, 0, plainText.length);
					// fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));
					System.out.printf(".");
					env = new Envelope("DOWNLOADF"); //Success
					env.setSequenceNum(this.sequenceNum++);
					lib.signEnvelope(env, integrityKey);
					lib.writeEncryptedObject(env, outStream, enCipher);
					env = (Envelope)lib.readEncryptedObject(inStream, deCipher);
					this.sequenceNum = lib.verifyEnvelope(env, integrityKey, this.sequenceNum);
					if (this.sequenceNum < 0) {
						return false;
					}
				}
				fos.close();

				if(env.getMessage().compareTo("EOF")==0) {
					fos.close();
					System.out.printf("\nTransfer successful file %s\n", sourceFile);
					env = new Envelope("OK"); //Success
					env.setSequenceNum(this.sequenceNum++);
					lib.signEnvelope(env, integrityKey);
					lib.writeEncryptedObject(env, outStream, enCipher);
				}
				else {
					System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
					file.delete();
					return false;
				}
			}

			else {
				System.out.printf("Error couldn't create file %s\n", destFile);
				return false;
			}


		} catch (IOException e1) {

			System.out.printf("Error couldn't create file %s\n", destFile);
			return false;


		}
		return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token) {
		processToken(token);
		try
		{
			Envelope message = null, e = null;
			//Tell the server to return the member list
			message = new Envelope("LFILES");
			message.addObject(token); //Add requester's token
			message.setSequenceNum(this.sequenceNum++);
			lib.signEnvelope(message, integrityKey);
			lib.writeEncryptedObject(message, outStream, enCipher);

			e = (Envelope)lib.readEncryptedObject(inStream, deCipher);
			this.sequenceNum = lib.verifyEnvelope(e, integrityKey, this.sequenceNum);
			if (this.sequenceNum < 0) {
				return null;
			}

			//If server indicates success, return the member list
			if(e.getMessage().equals("OK"))
			{
				return (List<String>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			} else {
				System.out.println("\nError: " + e.getMessage() + "\n");
				return null;
			}


		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	public boolean upload(String sourceFile, String destFile, String group,
		UserToken token) {

		processToken(token);

		// SimpleToken simpleToken = (SimpleToken)token;
		// HashMap<String, GroupKey> keyMap = simpleToken.getGroupKeys(); // get all group keys from the token
		// simpleToken.removeKeys(); // remove the keys from the token

		if (destFile.charAt(0)!='/') { // get the destination file name
			destFile = "/" + destFile;
		}

		try
		{

			FileInputStream fis = new FileInputStream(sourceFile); // open file output stream from source file
			// Key fileKey; // the current key to encrypt the file
			// byte[] ivBytes = lib.getIVBytes(); // generate random iv for this file
			Cipher fileEnCipher;


			Envelope message = null, env = null;
			//Tell the server to return the member list
			message = new Envelope("UPLOADF"); // upload hand shake
			message.addObject(destFile); // remote file name
			message.addObject(group); // upload to a group
			message.addObject(token); //Add requester's token
			message.setSequenceNum(this.sequenceNum++);
			lib.signEnvelope(message, integrityKey);
			lib.writeEncryptedObject(message, outStream, enCipher);

			// TODO: add new steps to transfer key info and group name in plain text
			env = (Envelope)lib.readEncryptedObject(inStream, deCipher); // get response
			this.sequenceNum = lib.verifyEnvelope(env, integrityKey, this.sequenceNum);
			if (this.sequenceNum < 0) {
				return false;
			}
			if (env.getMessage().equals("READY FOR FILE HEADER")) {
				message = new Envelope("FILE HEADER"); // create new envelope for file header
				GroupKey gk = keyMap.get(group);
				byte[] ivBytes = lib.getIVBytes();
				message.addObject(gk.generateKeyInfo());
				message.addObject(group);
				message.addObject(ivBytes); // add the iv to the file header too
				Key fileKey = gk.getCurrentKey(); // get the current key to encrypt the file
				fileEnCipher = lib.getFileEnCipher(fileKey, ivBytes); // get the cipher from the current key and iv
				message.setSequenceNum(this.sequenceNum++);
				lib.signEnvelope(message, integrityKey);
				lib.writeEncryptedObject(message, outStream, enCipher);
			} else {
				System.out.println("server side error on file header");
				return false;
			}

			env = (Envelope)lib.readEncryptedObject(inStream, deCipher); // get response
			this.sequenceNum = lib.verifyEnvelope(env, integrityKey, this.sequenceNum);
			if (this.sequenceNum < 0) {
				return false;
			}

			if(env.getMessage().equals("READY"))
			{
				System.out.printf("Meta data upload successful\n");
			}
			else {
				System.out.printf("Upload failed: %s\n", env.getMessage());
				return false;
			}


			do {
				
				byte[] buf = new byte[4095]; // need 4095 because 4096 will add another block to the encrypted bytes
				
				if (env.getMessage().compareTo("READY")!=0) { // check if server is ready for chunk message
					System.out.printf("Server error: %s\n", env.getMessage());
					return false;
				}
				message = new Envelope("CHUNK");
				int n = fis.read(buf); //can throw an IOException
				if (n > 0) {
					System.out.printf(".");
				} else if (n < 0) {
					System.out.println("Read error");
					return false;
				}

				byte[] plainText;
				if (n == buf.length) {
					plainText = buf;
				} else { // remove unused part
					plainText = Arrays.copyOfRange(buf, 0, n);
				}


				byte[] cipherText = lib.encrypt(plainText, fileEnCipher);
				n = cipherText.length;
				// System.out.println("cipher text length: " + n);

				// message.addObject(buf);
				message.addObject(cipherText);
				message.addObject(new Integer(n));
				message.setSequenceNum(this.sequenceNum++);

				lib.signEnvelope(message, integrityKey);
				lib.writeEncryptedObject(message, outStream, enCipher);


				env = (Envelope)lib.readEncryptedObject(inStream, deCipher);
				this.sequenceNum = lib.verifyEnvelope(env, integrityKey, this.sequenceNum);
				if (this.sequenceNum < 0) {
					return false;
				}


			}
			while (fis.available()>0);

			//If server indicates success, return the member list
			if(env.getMessage().compareTo("READY")==0)
			{

				message = new Envelope("EOF");
				// output.writeObject(message);
				// lib.writeObject(message, outStream);
				message.setSequenceNum(this.sequenceNum++);
				lib.signEnvelope(message, integrityKey);
				lib.writeEncryptedObject(message, outStream, enCipher);

				env = (Envelope)lib.readEncryptedObject(inStream, deCipher);
				this.sequenceNum = lib.verifyEnvelope(env, integrityKey, this.sequenceNum);
				if (this.sequenceNum < 0) {
					return false;
				}
				if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
				}
				else {

					System.out.printf("\nUpload failed: %s\n", env.getMessage());
					return false;
				}

			}
			else {

				System.out.printf("Upload failed: %s\n", env.getMessage());
				return false;
			}

		} catch (FileNotFoundException fnfe) {
			System.out.println("File doesn't exsit. " + fnfe.getMessage());
			return false;

		} catch(Exception e1)
		{
			System.err.println("Error: " + e1.getMessage());
			e1.printStackTrace(System.err);
			return false;
		}
		return true;
	}
	
	//Override disconnect() in Client.java
	public void disconnect() {
		if (isConnected()) {
			try
			{
				Envelope message = new Envelope("DISCONNECT");
				message.setSequenceNum(this.sequenceNum++);
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
