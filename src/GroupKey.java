import java.util.ArrayList;
import java.io.Serializable;
import java.security.Key;

public class GroupKey implements Serializable{

  private static final long serialVersionUID = 5666017279424019915L;
  public ArrayList<byte[]> materialList;
  public byte[] currentKeyMaterial;
  public int currentKeyIndex;
  public int currentHashCount;

  public GroupKey(){}

  public GroupKey(ArrayList<byte[]> materialList, byte[] currentKeyMaterial, int currentKeyIndex, int currentHashCount) {
    this.materialList = materialList;
    this.currentKeyMaterial = currentKeyMaterial;
    this.currentKeyIndex = currentKeyIndex;
    this.currentHashCount = currentHashCount;
  }

  // generate the key info bytes from the current group key
  public byte[] generateKeyInfo() {
    byte[] info = new byte[3];
    info[0] = (byte)(currentKeyIndex / 256);
    info[1] = (byte)(currentKeyIndex % 256);
    info[2] = (byte)currentHashCount;
    return info;
  }

  public Key getCurrentKey() {
    SecurityLib lib = SecurityLib.getInstance();
    return lib.getFileKey(this, this.generateKeyInfo());
  }

  @Override
  public String toString() {
    return "" + 
    materialList +
    currentKeyMaterial +
    currentKeyIndex +
    currentHashCount;
  }
}
