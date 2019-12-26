import java.util.List;
import java.util.HashMap;
import java.io.Serializable;
import java.util.concurrent.TimeUnit;


public class SimpleToken implements UserToken, Serializable{

  private static final long serialVersionUID = -5172889460800513297L;
  private String issuer;
  private String subject;
  private List<String> groups;
  private byte[] signature; // the signature to verify that the token is actually issued by the group server
  private HashMap<String, GroupKey> groupKeys; // group keys to decrypt files, need to remove this one before sending to the file server
  private long timeStamp;
  private String fileServerPubKeyString;

  public SimpleToken(String issuer, String subject, List<String> groups) {
    this.issuer = issuer;
    this.subject = subject;
    this.groups = groups;
    this.timeStamp = System.currentTimeMillis();
  }

  public SimpleToken(String issuer, String subject, List<String> groups, String fileServerPubKeyString, HashMap<String, GroupKey> gkMap) {
    this(issuer, subject, groups);
    this.fileServerPubKeyString = fileServerPubKeyString;
    this.groupKeys = gkMap;
  }

  public void setFilePubKey(String pubKeyString) {
    this.fileServerPubKeyString = pubKeyString;
  }

  public String getFilePubKey() {
    return this.fileServerPubKeyString;
  }

  public String getIssuer() {
    return this.issuer;
  }

  public String getSubject() {
    return this.subject;
  }

  public List<String> getGroups() {
    return this.groups;
  }

  // get the signature of the token
  public byte[] getSignature() {
    return this.signature;
  }

  // set the signature of the token
  public void setSignature(byte[] signature) {
    this.signature = signature;
  }


  // use this as the string representation of the object for hashing
  // ',' is the separator, so, when creating group, ',' should not be in the name
  public String toString() {
    String rtn = this.issuer + "," + subject + "," + this.timeStamp + "," + this.fileServerPubKeyString;
    for (String s : groups) {
      rtn += "," + s;
    }
    return rtn;
  }

  // get the group key by name, seems not useful at all because need to remove the key from the token at first
  public GroupKey getGroupKey(String groupName) {
    return this.groupKeys.get(groupName);
  }

  // get all group keys
  public HashMap<String, GroupKey> getGroupKeys() {
    return this.groupKeys;
  }

  public void setGroupKes(HashMap<String, GroupKey> map) {
    this.groupKeys = map;
  }

  // remove the keys before sending to file server
  public void removeKeys() {
    this.groupKeys = null;
  }

  // verify the time stamp of the given token
  public boolean verifyTime() {
    return System.currentTimeMillis() - this.timeStamp < TimeUnit.DAYS.toMillis(1); // timeout is 1 day
  }
}
