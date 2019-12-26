import java.util.*;

public class ClientApp {
	static UserToken token;
	static String username;
	static String password;

	private static FileClient connectFileServer() {
		FileClient rtn = new FileClient();
		Scanner kbd = new Scanner(System.in);
		System.out.println("Please input the file server IP address:");
		String ip = kbd.nextLine();
		System.out.println("Please input the file server port (default 4321):");
		int fport = 4321;
		String tempInput = kbd.nextLine();
		if (!tempInput.equals("")) {
			try {
				fport = Integer.parseInt(tempInput);
			} catch (Exception e) {
				System.out.println("Invalid port!");
				System.exit(0);
			}
		}
		boolean isconnected = false;
		try {
			isconnected = rtn.connect(ip, fport);
		} catch (Exception e) {
			System.out.println("Cannot connect to the server" + ip);
			System.exit(0); // exit because cannot connect to the server
		}
		if (isconnected)
			return rtn;
		else {
			System.out.println("File Server connection failed");
			return null;
		}

	}

	private static GroupClient connectGroupServer() {
		GroupClient rtn = new GroupClient();
		Scanner kbd = new Scanner(System.in);
		System.out.println("Please input the group server IP address:");
		String ip = kbd.nextLine();
		System.out.println("Please input the group server port (default 8765):");
		int gport = 8765;
		String tempInput = kbd.nextLine();
		if (!tempInput.equals("")) {
			try {
				gport = Integer.parseInt(tempInput);
			} catch (Exception e) {
				System.out.println("Invalid port!");
				System.exit(0);
			}
		}
		System.out.println("Username: ");
		username = kbd.nextLine();
		System.out.println("Password: ");
		password = kbd.nextLine();

		boolean isconnected = false;
		try {
			isconnected = rtn.connect(ip, gport, username, password);
		} catch (Exception e) {
			System.out.println("Cannot connect to the server" + ip);
			System.exit(0); // exit because cannot connect to the server
		}
		if (isconnected)
			return rtn;
		else {
			System.out.println("Group Server connection failed");
			return null;
		}
	}

	private static void getUserToken(GroupClient gclient) {
		token = gclient.getToken();
	}

	private static void printMenu() {
		System.out.println("\n\nUser: " + token.getSubject());
		System.out.println("Please select operation:\n");
		System.out.println("0 Exit");
		System.out.println("1 List files");
		System.out.println("2 Upload file");
		System.out.println("3 Download file");
		System.out.println("4 Delete file");
		System.out.println("5 Delete user from a group");
		System.out.println("6 Add user to a group");
		System.out.println("7 List members of a group");
		System.out.println("8 Delete a group");
		System.out.println("9 Create a group");
		System.out.println("10 Delete a user");
		System.out.println("11 Create a user");
		System.out.println("12 Change password");
	}

	private static int getUserCommand() {
		Scanner scanner = new Scanner(System.in);
		boolean valid = false;
		int command = -1;
		do {
			System.out.print("Enter the command (0-12) : ");
			String userInput = scanner.nextLine();
			try {
				command = Integer.parseInt(userInput);
				if (command >= 0 && command <= 12)
					valid = true;
				else
					System.out.println("Invalid input, pleas try again. ");
			} catch (Exception e) {
				System.out.println("Invalid input, pleas try again. ");
			}
		} while (!valid);
		return command;
	}

	private static void listFiles(FileClient client) {
		List<String> fileList = client.listFiles(token);
		for (String name : fileList) {
			System.out.println(name);
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
	private static void uploadFile(FileClient client) {
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
	private static void downloadFile(FileClient client) {
		String sourceFile = getUserStringInput("Please enter the file name to download");
		String destFile = getUserStringInput("Please enter the new file name");
		if (client.download(sourceFile, destFile, token)) {
			System.out.println("Download succeeded!");
		} else {
			System.out.println("Download failed...");
		}
	}

	// delete a file
	private static void deleteFile(FileClient client) {
		String filename = getUserStringInput("Please enter the file name to delete");
		if (client.delete(filename, token)) {
			System.out.println("Delete succeeded!");
		} else {
			System.out.println("Delete failed...");
		}
	}

	private static void dUserFromGroup(GroupClient gclient) {
		String user = getUserStringInput("Deleteing user from a group...\nEnter a user to remove: ");
		String group = getUserStringInput("Enter a group to remove the user from: ");
		boolean result = false;
		result = gclient.deleteUserFromGroup(user, group, token);
		if (!result) {
			System.out.println("Error in removing user from group");
		}
		// after group operation, the token may be changed, so need to get the token
		// again
		getUserToken(gclient);
	}

	private static void aUserToGroup(GroupClient gclient) {
		String user = getUserStringInput("Adding a user to a group...\nEnter a user: ");
		String group = getUserStringInput("Enter the group to add: ");
		boolean result = false;
		result = gclient.addUserToGroup(user, group, token);
		if (!result) {
			System.out.println("Error in adding group to user - ensure token is an admin or owner of the group");
		}
		// after group operation, the token may be changed, so need to get the token
		// again
		getUserToken(gclient);
	}

	private static void listGroupMember(GroupClient gclient) {
		String group = getUserStringInput("Listing group memebrs...\nEnter a groupname:");
		List<String> members = (List<String>) gclient.listMembers(group, token);
		if (members == null) {
			System.out.println("Error in listing members of group " + group);
			return;
		}
		System.out.println("Members in " + group + ":\n");
		for (String member : members) {
			System.out.println(member);
		}
	}

	private static void dGroup(GroupClient gclient) {
		String group = getUserStringInput("Deleting group...\nEnter group to delete: ");
		boolean result = false;
		result = gclient.deleteGroup(group, token);
		if (!result) {
			System.out.println("Error in deleting group" + group);
		}
		// after group operation, the token may be changed, so need to get the token
		// again
		getUserToken(gclient);
	}

	private static void cGroup(GroupClient gclient) {
		String group = getUserStringInput("Creating group...\nEnter group name: ");
		boolean result = false;
		result = gclient.createGroup(group, token);
		if (!result) {
			System.out.println("Error in creating group");
		}
		// after group operation, the token may be changed, so need to get the token
		// again
		getUserToken(gclient);
	}

	private static void dUser(GroupClient gclient) {
		String user = getUserStringInput("Deleting user...\nEnter username to delete: ");
		boolean result = false;
		result = gclient.deleteUser(user, token);
		if (!result) {
			System.out.println("Error in deleting user");
		}
	}

	private static void cUser(GroupClient gclient) {
		// Only ADMINS can create new users, must be an ADMIN token
		String user = getUserStringInput("Creating user...\nEnter username: ");
		boolean result = false;
		String passW = getUserStringInput("Enter password: ");
		while (passW.equals(null) || passW.length() < 8) {
			passW = getUserStringInput("Enter password (minimum 8 characters): ");
		}
		result = gclient.createUser(user, passW, token);
		if (!result) {
			System.out.println("Error in creating user");
		}
	}

	private static void doFileOperation(int command, FileClient fclient) {
		assert (command >= 1 && command <= 4);
		switch (command) {
		case 0:
			System.out.println("Exit...");
			break;
		case 1:
			listFiles(fclient);
			break;
		case 2:
			uploadFile(fclient);
			break;
		case 3:
			downloadFile(fclient);
			break;
		case 4:
			deleteFile(fclient);
		}
	}

	private static void doGroupOperation(int command, GroupClient gclient) {
		assert (command >= 5 && command <= 12);
		switch (command) {
		case 5:
			dUserFromGroup(gclient);
			break;
		case 6:
			aUserToGroup(gclient);
			break;
		case 7:
			listGroupMember(gclient);
			break;
		case 8:
			dGroup(gclient);
			break;
		case 9:
			cGroup(gclient);
			break;
		case 10:
			dUser(gclient);
			break;
		case 11:
			cUser(gclient);
			break;
		case 12:
			// Change user's password
			System.out.println("Change user's password... ");
			String oldPassword = getUserStringInput("Enter the old password: ");
			if (oldPassword.equals(password)) {
				String newPassword = getUserStringInput("Enter the new password: ");
				boolean result = false;
				result = gclient.changePassword(newPassword, token);
				if (!result) {
					System.out.println("Error in changing password");
				} else
					password = newPassword;
				getUserToken(gclient);
			} else
				System.out.println("Old password does not match!");
			break;
		}
	}

	public static void main(String[] args) {
		if (args.length > 0) {
			System.out.println("Usage: java ClientApp");
			System.exit(0);
		}
		FileClient fclient = connectFileServer();
		GroupClient gclient = connectGroupServer();
		if (fclient == null || gclient == null) {
			System.exit(-1);
		}
		getUserToken(gclient);
		if (token == null) {
			System.out.println("Error: User was not found\nDisconnecting...");
			fclient.disconnect();
			gclient.disconnect();
			System.exit(-1);
		}
		int command = -1;
		do {
			printMenu(); // prompt the menu for user to use
			command = getUserCommand();
			if (command > 0 && command <= 4) {
				doFileOperation(command, fclient);
			} else if (command >= 5 && command <= 12) {
				doGroupOperation(command, gclient);
			} else if (command == 0) {
				System.out.println("Exit...");
				break;
			}

		} while (command != 0);
		fclient.disconnect();
		gclient.disconnect();
	}
}