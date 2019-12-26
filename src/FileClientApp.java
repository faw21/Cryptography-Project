import java.util.List;
import java.util.ArrayList;
import java.util.Scanner;
import java.security.PrivateKey;
import java.util.HashMap;
import java.security.PublicKey;
public class FileClientApp {

  // print the usage message on the screen to the user
  private static void printUsage() {
    System.out.println("java FileClientApp address [port]");
  }

  // get a token in whatever way
  private static UserToken getUserToken() {
    List<String> groups = new ArrayList<String>();
    groups.add("group1");
    groups.add("group2");
    groups.add("group3");
    SimpleToken token =  new SimpleToken("group server1", "di", groups);

    // sign the token for testing
    SecurityLib lib = SecurityLib.getInstance();

    PublicKey pubKey = lib.readPublicKeyFromFile("file_public.key");
    // PublicKey pubKey = lib.readPublicKeyFromFile("group_public.key");
    token.setFilePubKey(lib.getPublicKeyString(pubKey));
    // PrivateKey privateKey = lib.readPrivateKeyFromFile("file_private.key");
    PrivateKey privateKey = lib.readPrivateKeyFromFile("group_private.key");
    lib.signToken(token, privateKey);
    GroupKeyManager manager1 = new GroupKeyManager();
    GroupKeyManager manager2 = new GroupKeyManager();
    GroupKeyManager manager3 = new GroupKeyManager();
    HashMap<String, GroupKey> keyMap = new HashMap<String, GroupKey>();
    keyMap.put("group1", manager1.getGroupKey());
    keyMap.put("group2", manager2.getGroupKey());
    keyMap.put("group3", manager3.getGroupKey());
    token.setGroupKes(keyMap);


    return token;
  }

  // print the menu for the user
  private static void printMenu() {
    System.out.println();
    System.out.println("0 exit");
    System.out.println("1 list files");
    System.out.println("2 upload file");
    System.out.println("3 download file");
    System.out.println("4 delete file");
    System.out.println();
  }

  // get the command integer from the user
  private static int getUserCommand() {
    Scanner scanner = new Scanner(System.in);
    boolean valid = false;
    int command = -1;
    do {
      System.out.print("Enter the command (1-4) : ");
      String userInput = scanner.nextLine();
      try {
        command = Integer.parseInt(userInput);
        if (command >= 0 && command <= 4) valid = true;
        else System.out.println("Invalid input, pleas try again. ");
      } catch (Exception e) {
        System.out.println("Invalid input, pleas try again. ");
      }
    } while (!valid);
    System.out.println();
    return command;
  }

  // connect to the server, address is given in the arguments
  private static FileClient connectServerInArgs(String[] args) {
    FileClient rtn = new FileClient();
    if (args.length < 1) {
      printUsage();
      System.exit(0); // exit because nothing to connect to
    }
    try {
      rtn.connect(args[0], 4321);
    } catch (Exception e) {
      System.out.println("Cannot connect to the server" + args[0]);
      System.exit(0); // exit because cannot connect to the server
    }
    return rtn;
  }

  private static void listFiles(UserToken token, FileClient client) {
    List<String> fileList = client.listFiles(token);
    if (fileList != null) {
      for (String name : fileList) {
        System.out.println(name);
      }
    }
  }

  // get the user input for file name and group name, repeat while it's empty
  private static String getUserStringInput(String prompt) {
    Scanner scanner = new Scanner(System.in);
    String input;
    do {
      System.out.print(prompt + " (can't be empty): ");
      input = scanner.nextLine();
    } while (input.length() == 0);
    return input;
  }

  // upload a file
  private static void uploadFile(UserToken token, FileClient client) {
    String sourceFile = getUserStringInput("Please enter the file name to upload");
    String destFile = getUserStringInput("Please enter the file name will be on the server");
    String group = getUserStringInput("Please enter the group name you want to upload to");
    if (client.upload(sourceFile, destFile, group, token)) {
      System.out.println("Upload succeeded!");
    } else {
      System.out.println("Upload failed...");
    }
  }

  // download a file
  private static void downloadFile(UserToken token, FileClient client) {
    String sourceFile = getUserStringInput("Please enter the file name to download");
    String destFile = getUserStringInput("Please enter the new file name");
    if (client.download(sourceFile, destFile, token)) {
      System.out.println("Download succeeded!");
    } else {
      System.out.println("Download failed...");
    }
  }

  // delete a file
  private static void deleteFile(UserToken token, FileClient client) {
    String filename = getUserStringInput("Please enter the file name to delete");
    if (client.delete(filename, token)) {
      System.out.println("Delete succeeded!");
    } else {
      System.out.println("Delete failed...");
    }
  }

  // do the operations according to the given valid user command (0-4)
  private static void doFileOperation(int command, UserToken token, FileClient client) {
    assert(command >= 0 && command <= 4);
    switch(command) {
      case 0:
        System.out.println("Exit...");
        break;
      case 1:
        listFiles(token, client);
        break;
      case 2:
        uploadFile(token, client);
        break;
      case 3:
        downloadFile(token, client);
        break;
      case 4:
        deleteFile(token, client);
    }
  }

  public static void main(String[] args) {
    // before connect to the file servers, should all ready have the token to be used (or maybe later, no matter)

    FileClient client = connectServerInArgs(args);
    UserToken token = getUserToken();

    // need to let the file client to process the token to get the key and remove it from token
    client.processToken(token);

    int command = -1;
    do {
      printMenu(); // prompt the menu for user to use
      command = getUserCommand();
      doFileOperation(command, token, client);
    } while (command != 0);
    client.disconnect();
  }
}
