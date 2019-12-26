import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;
import java.security.Provider;
import javax.crypto.KeyGenerator;
import java.security.KeyPairGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Scanner;
import java.util.Random;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.ArrayList;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.security.SecureRandom;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import javax.crypto.Mac;

public class SecurityLib {
  private static final String PROVIDER_NAME = "BC";
  private static final String PUBLIC_KEY_ALGORITHM = "RSA";
  private static final String DH_ALGORITHM = "DH";
  private static final String SYMMETRIC_KEY_ALGORITHM = "AES/CBC/PKCS5Padding";
  private static final String RANDOM_ALGORITHM = "SHA1PRNG";
  private static final String HASH_ALGORITHM = "SHA-256";
  private static final String HMAC_ALGORITHM = "HmacSHA256";
  private static final int BLOCK_SIZE = 16;
  private static final int RSA_LENGTH = 4096;
  private static final int DH_LENGTH = 1024;
  private static final int AES_KEY_LENGTH = 256;
  private static SecurityLib instance = null;
  private Key plainKey = null;
  private Cipher plainEnCipher = null;
  private Cipher plainDeCipher = null;
  // g
  // p

  // private constructor to ensure singleton
  private SecurityLib() {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    this.plainKey = this.generateKeyFromPassword("hello"); // just some agreed key to do plaintext transfer
    IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]); // also, some blank iv for plaintext transfer
    this.plainEnCipher = this.getCipher(SYMMETRIC_KEY_ALGORITHM, this.plainKey, Cipher.ENCRYPT_MODE, ivSpec);
    this.plainDeCipher = this.getCipher(SYMMETRIC_KEY_ALGORITHM, this.plainKey, Cipher.DECRYPT_MODE, ivSpec);
  }

  // singleton instance getter
  // use "SecurityLib lib = SecurityLib.getInstance()" to get the singleton instance of the class
  public static SecurityLib getInstance() {
    if (SecurityLib.instance == null) {
      SecurityLib.instance = new SecurityLib();
    }
    return SecurityLib.instance;
  }



  // get the symmetric encrypt cipher
  public Cipher getSymmetricEnCipher(Key key, IvParameterSpec ivSpec) {
    return this.getCipher(SYMMETRIC_KEY_ALGORITHM, key, Cipher.ENCRYPT_MODE, ivSpec);
  }

  // get the symmetric decrypt cipher
  public Cipher getSymmetricDeCipher(Key key, IvParameterSpec ivSpec) {
    return this.getCipher(SYMMETRIC_KEY_ALGORITHM, key, Cipher.DECRYPT_MODE, ivSpec);
  }

  public Cipher getFileEnCipher(Key key, byte[] ivBytes) {
    return this.getSymmetricEnCipher(key, new IvParameterSpec(ivBytes));
  }

  public Cipher getFileDeCipher(Key key, byte[] ivBytes) {
    return this.getSymmetricDeCipher(key, new IvParameterSpec(ivBytes));
  }

  // get cipher with iv (for symmetric cipher)
  private Cipher getCipher(String algorithm, Key key, int mode, IvParameterSpec ivSpec) {
    try {
      Cipher cipher = Cipher.getInstance(algorithm, PROVIDER_NAME);
      // IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
      cipher.init(mode, key, ivSpec);
      return cipher;
    } catch (Exception e) {
      System.out.println("can't get cipher");
      System.out.println(e);
      return null;
    }
  }

  // get cipher without iv (for rsa cipher)
  private Cipher getCipher(String algorithm, Key key, int mode) {
    try {
      Cipher cipher = Cipher.getInstance(algorithm, PROVIDER_NAME);
      cipher.init(mode, key);
      return cipher;
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  // generate a key from given password, it's deterministic
  // TODO: this part need to reimplement, to make sure the key will be deterministic and safe
  // I think group part will need this one, I will modify this later, but for now just use it
  public Key generateKeyFromPassword(String password) {
    // byte[] salt = new byte[16]; // the salt will be all 0 for now
    // PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256); // generate a 256-bit key spec
    try {
      // Key key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", SecurityLib.PROVIDER_NAME).generateSecret(spec);
      // Key key = new SecretKeySpec(new byte[32], "AES");
      Key key = new SecretKeySpec(getHash(password), "AES");
      return key;
    } catch (Exception e) {
      System.out.println("can't generate key from password");
      System.out.println(e);
      return null;
    }
  }


  // convert object to bytes, will also be used in hmac signature
  public byte[] objectToBytes(Object o) {
    try {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      ObjectOutputStream os = new ObjectOutputStream(baos);
      os.writeObject(o);
      byte[] arr = baos.toByteArray();
      return arr;
    } catch (Exception e) {
      System.out.println("can't convert object to byte array");
      System.out.println(e);
      return null;
    }
  }


  // convert bytes to object
  // declare as public for test usage, don't call this one in production code
  public Object bytesToObject(byte[] bytes) {
    try {
      ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
      return ois.readObject();
    } catch (Exception e) {
      e.printStackTrace();
      System.out.println("can't convert bytes to object");
      System.out.println(e);
      return null;
    }
  }

  public byte[] combineByteArrays(byte[] b1, byte[] b2) {
    if (b1 == null) {
      return b2;
    }
    byte[] rtn = new byte[b1.length + b2.length];
    System.arraycopy(b1, 0, rtn, 0, b1.length);
    System.arraycopy(b2, 0, rtn, b1.length, b2.length);
    return rtn;
  }

  public byte[] encrypt(byte[] plainText, Cipher cipher) {
    try {
      if (plainText.length <= 16) { // if can be solved in a block, just doFinal
        return cipher.doFinal(plainText);
      }
      // System.out.println(cipher + " " + plainText);
      byte[] previous = cipher.update(plainText);
      return combineByteArrays(previous, cipher.doFinal());
    } catch (Exception e) {
      e.printStackTrace();
      System.out.println("cannot encrypt");
      return null;
    }
  }

  public byte[] decrypt(byte[] cipherText, Cipher cipher) {
    try {
      if (cipherText.length <= 16) {// if can be solved in a block, just doFinal
        return cipher.doFinal(cipherText);
      }
      byte[] previous = cipher.update(cipherText);
      return combineByteArrays(previous, cipher.doFinal());
    } catch (Exception e) {
      e.printStackTrace();
      System.out.println("cannot encrypt");
      return null;
     }
  }

  // read object in plain text
  public Object readObject(InputStream in) {
    return this.readEncryptedObject(in, this.plainDeCipher);
  }

  // read object with symmetric cipher
  public Object readEncryptedObject(InputStream in, Cipher cipher) {
    try {
      byte[] objectBytes = readCipherBlocks(in, cipher);
      return bytesToObject(objectBytes);
    } catch (Exception e) {
      e.printStackTrace();
      System.out.println("cannot read encrypted object");
      return null;
    }
  }

  // write object in plain text
  public boolean writeObject(Object o, OutputStream out) {
    return writeEncryptedObject(o, out, this.plainEnCipher);
  }

  // write object with symmetric cipher
  public boolean writeEncryptedObject(Object o, OutputStream out, Cipher cipher) {
    try {
      byte[] objectBytes = objectToBytes(o);
      byte[] cipherText = encrypt(objectBytes, cipher);
      out.write(cipherText);
      return true;
    } catch (Exception e) {
      e.printStackTrace();
      System.out.println("cannot write encrypted object");
      return false;
    }
  }

  // process the given list of byte[] with length 16, combine them together, decrypt and return the byte array
  private byte[] processBlocks(ArrayList<byte[]> blocks, Cipher c) {
    byte[] allBytes = new byte[16 * blocks.size()];
    // System.out.println("curr trying length: " + allBytes.length);
    for (int i=0; i<blocks.size(); i++) {
      for (int j=0; j<16; j++) {
        allBytes[i * 16 + j] = blocks.get(i)[j];
      }
    }
    // System.out.println("before processing bytes length: " + allBytes.length);
    return decrypt(allBytes, c);
  }

  // read and process cipher blocks
  // should use decrypt cipher to get plain text
  private byte[] readCipherBlocks(InputStream in, Cipher c) {
    ArrayList<byte[]> blocks = new ArrayList<byte[]>();
    // boolean processable = false;
    try {
      do {
        //byte[] newBlock = in.readNBytes(16);
        byte[] newBlock = new byte[16];
        in.read(newBlock);

        blocks.add(newBlock);
      } while (in.available() != 0);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return processBlocks(blocks, c);
  }

  // generate keypair with default setting
  // this is for generate rsa key pair, for DH key pair see "generateKeyPairDH"
  public KeyPair generateKeyPair() {
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance(PUBLIC_KEY_ALGORITHM, PROVIDER_NAME);
      kpg.initialize(RSA_LENGTH);
      KeyPair kp = kpg.generateKeyPair();
      return kp;
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  // write the given key to file as an object
  public void writeKeyToFile(Key key, String filename) {
    try {
      File file = new File(filename);
      FileOutputStream fileOutputStream = new FileOutputStream(file);
      ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
      objectOutputStream.writeObject(key);
      objectOutputStream.close();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  // read a public key from a file
  // I believe if the content of the file is not a public key, this will return null
  public PublicKey readPublicKeyFromFile(String filename) {
    try {
      File file = new File(filename);
      FileInputStream fileInputStream = new FileInputStream(file);
      ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
      return (PublicKey) objectInputStream.readObject();
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  // read a private key from a file
  // I believe if the content of the file is not a private key, this will return null
  public PrivateKey readPrivateKeyFromFile(String filename) {
    try {
      File file = new File(filename);
      FileInputStream fileInputStream = new FileInputStream(file);
      ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
      return (PrivateKey) objectInputStream.readObject();
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  // get the decrypt cipher from the given private key
  public Cipher getPublicKeyDeCipher(PrivateKey key) {
    return getCipher(PUBLIC_KEY_ALGORITHM, key, Cipher.DECRYPT_MODE);
  }

  // get the encrypt cipher from the given public key
  public Cipher getPublicKeyEnCipher(PublicKey key) {
    return getCipher(PUBLIC_KEY_ALGORITHM, key, Cipher.ENCRYPT_MODE);
  }

  // TODO: should be private
  public byte[] generateRandomBytes(int size) {
    try{
      SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
      byte[] r = new byte[size];
      random.nextBytes(r);
      return r;
    } catch (Exception e) {
      System.out.println("can't generate random bytes");
      return null;
    }
  }
  // generate a random byte[] as the challenge used in protocols
  public byte[] generateChallenge() {
    // try {
    //   // SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM, PROVIDER_NAME);
    //   SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
    //   byte[] challenge = new byte[128];
    //   random.nextBytes(challenge);
    //   return challenge;
    // } catch (Exception e) {
    //   e.printStackTrace();
    //   return null;
    // }
    return generateRandomBytes(128);
  }

  // change the first byte of the challenge by adding 1
  public byte[] responseChallenge(byte[] original) {
    byte[] rtn = original.clone();
    rtn[0] = (byte) (original[0] + 1);
    return rtn;
  }

  // check if the response challenge is valid comparing to the original challenge
  public boolean verifyChallenge(byte[] original, byte[] returned) {
    if (original.length != returned.length) {
      return false;
    } else {
      byte a = original[0];
      byte b = returned[0];
      if (b != (byte)(a + 1)) { // the first byte of the array is incremented by 1
        return false;
      }
      for (int i=1; i<original.length; i++) {
        if (original[i] != returned[i]) {
          return false;
        }
      }
      return true;
    }
  }



  // TODO: the input might be too large, need to make sure all key length in good randge(for now it's good enough)
  // sign the given byte[] and return the signature
  public byte[] sign(byte[] toSign, PrivateKey privateKey) {
    try {
      Signature sig = Signature.getInstance(PUBLIC_KEY_ALGORITHM, PROVIDER_NAME);
      sig.initSign(privateKey);
      sig.update(toSign);
      return sig.sign();
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  // verify the given byte[] with signature and public key
  public boolean verify(byte[] toVerify, byte[] signature, PublicKey publicKey) {
    try {
      Signature sig = Signature.getInstance(PUBLIC_KEY_ALGORITHM, PROVIDER_NAME);
      sig.initVerify(publicKey);
      sig.update(toVerify);
      return sig.verify(signature);
    } catch (Exception e) {
      e.printStackTrace();
      return false;
    }
  }


  // part of diffie hellman
  // generate the key pair for one user
  // both user and server need to generate key pairs
  public KeyPair generateKeyPairDH() {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance(DH_ALGORITHM, PROVIDER_NAME);
      generator.initialize(DH_LENGTH);
      return generator.generateKeyPair();
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  // part of diffie hellman
  // use my own keypair and another one's public key to get shared secret (in bytes)
  // on both sides, the content of the byte array will be the same
  // @aKey: the key pair one side have
  // @bPubKeyEncode: the public key encoded from the other side
  public byte[] getSharedSecret(KeyPair aKey, byte[] bPubKeyEncode) {
    try {
      KeyFactory keyFactory = KeyFactory.getInstance(DH_ALGORITHM, PROVIDER_NAME);
      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bPubKeyEncode);
      PublicKey bPubKey = keyFactory.generatePublic(keySpec);
      KeyAgreement agree = KeyAgreement.getInstance(DH_ALGORITHM, PROVIDER_NAME);
      agree.init(aKey.getPrivate());
      agree.doPhase(bPubKey, true);
      return agree.generateSecret();
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  // get the random bytes for IV, simply "new IvParameterSpec(bytes[])" to generate IV with the result of the method
  public byte[] getIVBytes() {
    // try {
    //   SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
    //   byte[] bytes = new byte[BLOCK_SIZE];
    //   random.nextBytes(bytes);
    //   return bytes;
    // } catch (Exception e) {
    //   e.printStackTrace();
    //   return null;
    // }
    return generateRandomBytes(BLOCK_SIZE);
  }

  // given bytes (shared secret after diffie hellman), generate the 256 bit aes key
  @Deprecated
  public Key getSymmetricKeyFromBytes(byte[] bytes) {
    return new SecretKeySpec(bytes, 0, 32, "AES");
  }

  // phase 4
  // given bytes (shared secret) and extra information (a single byte to indicate the usage of the key), generate the 256 bit aes key
  // tested
  private Key getSymmetricKeyFromBytes(byte[] bytes, byte extra, String algorithm) {
    byte[] newSecret = combineByteArrays(bytes, new byte[] {extra});
    byte[] hashSecret = getHash(newSecret);
    return new SecretKeySpec(hashSecret, 0, 32, algorithm);
  }

  public Key getSymmetricKeyForCipher(byte[] secret) {
    return getSymmetricKeyFromBytes(secret, (byte)0, "AES");
  }

  public Key getSymmetricKeyForHMAC(byte[] secret) {
    return getSymmetricKeyFromBytes(secret, (byte)1, HMAC_ALGORITHM);
  }

  // test methods to show all bytes of a byte[]
  public void showBytes(byte[] bytes) {
    System.out.println(toHexString(bytes));
    // if (bytes == null) {
    //   System.out.println("null");
    // } else {
    //   for (int i=0; i<bytes.length; i++) {
    //     System.out.print(bytes[i] + ":");
    //   }
    // }
  }

  // get the hash bytes of the given string message
  private byte[] getHash(String message) {
    try {
      MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
      byte[] hash = digest.digest(message.getBytes(StandardCharsets.UTF_8));
      return hash;
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  private byte[] getHash(byte[] bytes) {
    try {
      MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
      byte[] hash = digest.digest(bytes);
      return hash;
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  // sign the given token with the given private Key
  // because the signature will be stored in the token, after signing, just send the token
  public void signToken(SimpleToken token, PrivateKey privateKey) {
    String message = token.toString();
    byte[] hash = getHash(message);
    byte[] signature = this.sign(hash, privateKey);
    token.setSignature(signature);
  }

  // verify the given token with the given public key
  // since the signature will be stored in the token, just call this method with public key to verify it
  public boolean verifyToken(UserToken token, PublicKey publicKey) {
    SimpleToken trueToken = (SimpleToken) token;
    String message = trueToken.toString();
    byte[] hash = getHash(message);
    return this.verify(hash, trueToken.getSignature(), publicKey) && trueToken.verifyTime();
  }

  // phase 4 tested
  // sign the given envelope with the given key
  public void signEnvelope(Envelope e, Key key) {
    try {
      Mac mac = Mac.getInstance(HMAC_ALGORITHM, PROVIDER_NAME);
      mac.init(key);
      byte[] signature = mac.doFinal(e.getBytesToSign());
      e.setHmac(signature);
    } catch (Exception ex) {
      ex.printStackTrace();
      System.out.println("can't sign envelope");
    }
  }

  // phase 4 tested
  // verify the given envelope with the given key
  private boolean verifyEnvelope(Envelope e, Key key) {
    try {
      byte[] signature = e.getHmac();
      Mac mac = Mac.getInstance(HMAC_ALGORITHM, PROVIDER_NAME);
      mac.init(key);
      byte[] calculated_signature = mac.doFinal(e.getBytesToSign());
      return compareBytes(signature, calculated_signature);
    } catch (Exception ex) {
      ex.printStackTrace();
      System.out.println("can't verify envelope");
      return false;
    }
  }

  // compare the two given byte array
  public boolean compareBytes(byte[] a, byte[] b) {
    if (a == null){
      return b == null;
    } else if (b == null){
      return false;
    } else if (a.length != b.length){
      return false;
    } else {
      for (int i=0; i<a.length; i++) {
        if (a[i] != b[i]) {
          return false;
        }
      }
      return true;
    }
  }


  // get the key index (the key base used in the key list) from key information byte
  private int getKeyIndex(byte[] keyInfo) {
    int first = keyInfo[0] & 0xFF;
    int second = keyInfo[1] & 0xFF;
    return first * 256 + second;
  }

  // get the hashCount of the key base to hash to from key information byte
  private int getHashCount(byte[] keyInfo) {
    int hashCount = keyInfo[2] & 0xFF;
    return hashCount;
  }

  // get a key by hashing the current material
  public Key getKeyByMultiHashing(byte[] currentMaterial, int hashCount, int currentCount) {
    int hashTimes = hashCount - currentCount;
    byte[] material = hashWithCount(currentMaterial, hashTimes);
    return getSymmetricKeyForCipher(material);
  }

  // hash the given base material to the given count times
  public byte[] hashWithCount(byte[] base, int hashCount) {
    byte[] hashedMaterial = base;
    for (int i=0; i<hashCount; i++) {
      hashedMaterial = getHash(hashedMaterial);
    }
    return hashedMaterial;
  }

  // get the key for decrypting according to the given info of keys and files
  private Key getFileKey(ArrayList<byte[]> bases, byte[] currentKeyMaterial, int currentKeyIndex, int currentHashCount, byte[] keyInfo) {
    int keyIndex = getKeyIndex(keyInfo);
    int hashCount = getHashCount(keyInfo);
    if (keyIndex > currentKeyIndex) {
      return null;
    } else if (keyIndex == currentKeyIndex && hashCount < currentHashCount) {
      return null;
    }
    if (keyIndex != currentKeyIndex) { // if the file is too old, need another base key material, find the base and hash it
      return getKeyByMultiHashing(bases.get(keyIndex), hashCount, 0);
    } else { // if the file using current key base material, just hash it
      return getKeyByMultiHashing(currentKeyMaterial, hashCount, currentHashCount);
    }
  }

  // phase 4
  // get the file key by given current group key and the keyInfo of the file
  public Key getFileKey(GroupKey groupKey, byte[] keyInfo) {
    return getFileKey(groupKey.materialList, groupKey.currentKeyMaterial, groupKey.currentKeyIndex, groupKey.currentHashCount, keyInfo);
  }

  // generate a random key material for aes key (used by group server to generate new file descrption key when run out)
  public byte[] generateKeyMaterial() {
    return generateRandomBytes(AES_KEY_LENGTH / 8);
  }

  /*
   * Converts a byte to hex digit and writes to the supplied buffer
   */
  private void byte2hex(byte b, StringBuffer buf) {
      char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
              '9', 'A', 'B', 'C', 'D', 'E', 'F' };
      int high = ((b & 0xf0) >> 4);
      int low = (b & 0x0f);
      buf.append(hexChars[high]);
      buf.append(hexChars[low]);
  }

  /*
   * Converts a byte array to hex string
   */
  private String toHexString(byte[] block) {
      StringBuffer buf = new StringBuffer();
      int len = block.length;
      for (int i = 0; i < len; i++) {
          byte2hex(block[i], buf);
          if (i < len-1) {
              buf.append(":");
          }
      }
      return buf.toString();
  }

  // get the string representing the public key
  public String getPublicKeyString(PublicKey key) {
    return toHexString(key.getEncoded());
  }

  // call this method every time a new envelope is received
  // @sequenceNum the expecting sequence number should be passed in, so remember it and update it with the return value of the method
  // @return -1 if something is wrong, positive number for the next expecting envelope seqeunce number
  public int verifyEnvelope(Envelope e, Key integrityKey, int sequenceNum) {
		SecurityLib lib = SecurityLib.getInstance();

		if(!lib.verifyEnvelope(e, integrityKey)) {
			System.out.println("Hmac error, envelope has been modified");
      return -1;
		}
		if(e.getSequenceNum() != sequenceNum) {
			System.out.printf("Expecting: %d, Got: %d, Sequence number error, might be replay attack, reorder or dropping envelopes", sequenceNum,e.getSequenceNum());
      return -1;
		}
    return sequenceNum + 1;
  }
}
