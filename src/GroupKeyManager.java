import java.io.Serializable;
import java.util.ArrayList;

public class GroupKeyManager implements Serializable {

  private static final long serialVersionUID = -6173560047095321138L;
  private ArrayList<byte[]> materialList;
  private byte[] currentKeyMaterial;
  private byte[] currentKeyBaseMaterial;
  private int currentKeyIndex;
  private int currentHashCount;

  public GroupKeyManager() {
    SecurityLib lib = SecurityLib.getInstance();
    this.materialList = new ArrayList<byte[]>(); // keep the new key base out of the list, only group should know that
    this.currentKeyBaseMaterial = lib.generateKeyMaterial();
    this.currentKeyMaterial = lib.hashWithCount(this.currentKeyBaseMaterial, 255);
    this.currentHashCount = 255;
    this.currentKeyIndex = 0;
  }

  // called when a user is removed from a group, a new key will be generated
  public void changeKey() {
    SecurityLib lib = SecurityLib.getInstance();
    if (currentHashCount == 0) {
      materialList.add(currentKeyBaseMaterial); // add the last key base into the old key list
      currentKeyBaseMaterial = lib.generateKeyMaterial();
      currentKeyIndex++;
      currentHashCount = 255;
      currentKeyMaterial = lib.hashWithCount(currentKeyBaseMaterial, 255);
    } else {
      currentHashCount--;
      currentKeyMaterial = lib.hashWithCount(currentKeyBaseMaterial, currentHashCount);
    }
  }

  public GroupKey getGroupKey() {
    return new GroupKey(materialList, currentKeyMaterial, currentKeyIndex, currentHashCount);
  }

  @Override
  public String toString() {
    return "" +
    materialList + 
    currentKeyMaterial + 
    currentKeyBaseMaterial +
    currentKeyIndex +
    currentHashCount;
  }
}
