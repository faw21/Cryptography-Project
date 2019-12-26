import java.util.List;
import java.util.ArrayList;
import java.util.Scanner;
import java.io.*;

public class GroupClientApp
{
  public static void main(String[] args)
  {
    if(args.length < 3)
    {
      System.out.println("Usage- java GroupClientApp [server] [port] [user]");
      System.exit(-1);
    }
    //Connect
    GroupClient client = connectServer(args);

    //Attempt initial token
    UserToken token = client.getToken();

    if(token == null)
    {
      System.out.println("Error: User " + args[2] + " was not found\nDisconnecting...");
      client.disconnect();
      System.exit(-1);
    }

    System.out.println("Initial token of: " + token.getSubject());

    //Menu
    Scanner scanner = new Scanner(System.in);
    String input;

    do {
      int choice = 0;
      System.out.println("");
      printMenu();
      System.out.print("Enter choice (1-8):");
      choice = Integer.parseInt(scanner.nextLine());
      boolean result = false;

      //Could these have been broken down to if statements? Yes
      //Should they be if statements? Probably
      //Am I changing it? If youa asked but its a dummy App so...
      switch (choice)
      {
        case 1:
        //    public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
          System.out.print("Deleteing user from a group...\nEnter a user to remove: ");
          String user1 = getInput(scanner);
          System.out.print("Enter a group to remove the user from: ");
          String group1 = getInput(scanner);
          result = client.deleteUserFromGroup(user1,group1,token);
          if(!result)
          {
            System.out.println("Error in removing user from group");
          }
          break;
        case 2:
        //    public boolean addUserToGroup(String username, String groupname, UserToken token)
          System.out.print("Adding a user to a group...\nEnter a user: ");
          String user2 = getInput(scanner);
          System.out.print("Enter the group to add: ");
          String group2 = getInput(scanner);
          result = client.addUserToGroup(user2, group2, token);
          if(!result)
          {
            System.out.println("Error in adding group to user - ensure token is an admin or owner of the group");
          }
          break;
        case 3:
          // public List<String> listMembers(String group, UserToken token)
          System.out.print("Listing group memebrs...\nEnter a groupname:");
          String groupname3 = getInput(scanner);
          List<String> members = (List<String>)client.listMembers(groupname3, token);
          if(members == null)
          {
            System.out.println("Error in listing members of group " + groupname3 );
            break;
          }
          System.out.println("Members in " + groupname3 + ":\n");
          for(String member : members) {
            System.out.println(member);
          }
          break;
        case 4:
          //public boolean deleteGroup(String groupname, UserToken token)
          System.out.print("Deleting group...\nEnter group to delete: ");
          String groupname4 = getInput(scanner);
          result = client.deleteGroup(groupname4, token);
          if(!result)
          {
            System.out.println("Error in deleting group" + groupname4);
          }
          break;
        case 5:
          //public boolean createGroup(String groupname, UserToken token)
          System.out.print("Creating group...\nEnter group name: ");
          String groupname5 = getInput(scanner);
          result = client.createGroup(groupname5, token);
          if(!result)
          {
            System.out.println("Error in creating group");
          }
          break;
        case 6:
          System.out.print("Deleting user...\nEnter username to delete: ");
          String username6 = getInput(scanner);
          result = client.deleteUser(username6, token);
          if(!result)
          {
            System.out.println("Error in deleting user");
          }
          break;
        case 7:
          //Only ADMINS can create new users, must be an ADMIN token
          System.out.print("Creating user...\nEnter username: ");
          String username7 = getInput(scanner);
          System.out.print("Enter password: ");
          String newUserPassword = getInput(scanner);
          result = client.createUser(username7, newUserPassword, token);
          if(!result)
          {
            System.out.println("Error in creating user");
          }
          break;
        case 8:
          /*System.out.print("Enter the user you want to get a token for: ");
          String user8 = getInput(scanner);
          SimpleToken tmp = (SimpleToken)client.getToken(user8);
          if(tmp == null)
          {
            System.out.println("Error in getting token for that user");
          }
          else
          {
            token = tmp;
          }*/
          break;
        case 9:
          System.out.println("Not Implemented yet");
        break;
        case -1:
          client.disconnect();
          System.exit(0);
        default:
          System.out.println("Invalid choice, please use one of the following:");
          printMenu();
      }

    } while (true);

  }

  private static String getInput(Scanner scan)
  {
    String out = scan.nextLine();

    while(out.equals(""))
    {
      
      System.out.println("Enter a valid input");
      out = scan.nextLine();
    }

    return out;
  }

  private static GroupClient connectServer(String[] args)
  {
    System.out.println("Attempting connect...");
    GroupClient gc = new GroupClient();
    if(!gc.connect(args[0], Integer.parseInt(args[1]), args[2], args[3]))
    {
      System.err.println("Ensure usage is correnct\n"
        +"Usage- java GroupClientApp [server] [port]");
        return null;
    }
    System.out.println("Success!");
    return gc;

  }

  private static void printMenu()
  {
    System.out.println("1: Delete user from Group\n"+
    "2: Add user to Group\n"+
    "3: list Members of a group\n"+
    "4: delete a group\n"+
    "5: create Group\n"+
    "6: delete User\n"+
    "7: create User\n"+
    "8: get a Token\n"+
    "9: debug - list all current users\n" +
    "-1: Exit\n"
    );
  }
}
