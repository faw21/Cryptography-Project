# Cryptography Term Project
### Aaron Wu ###
### 2019 Fall ###
---

### Compile and Usage ###
Once inside src/ folder,
**COMPILE: 
```
javac -cp path/to/bouncy/castle/jar *.java
```

 ### USAGE: ###
  - To start Group Server: 
 ```
 java -cp .:/path/to/BC/jar RunGroupServer [(optional) port number]
 ```
 
 When the group server is first started, there are no users or groups. Since
 there must be an administer of the system, the user is prompted via the console
 to enter a username. This name becomes the first user and is a member of the
 ADMIN group.  Also, no groups exist.  The group server will by default
 run on port 8765, but a custom port can be passed as the first command line
 argument.

  - To start the File Server: 

 Ensure the Group Server public key is in the same directory as the stored File server
 
 ```
 java RunFileServer -cp .:/path/to/BC/jar [(optional) port number]
 ```
 
 The file server will create a shared_files inside the working directory if one
 does not exist. The file server is now online.  The file server will by default
 run on port 4321, but a custom port can be passed as the first command line
 argument.

 To reset the File server completely, delete FileList.bin and the shared_files
 directory.
 
 To reset the Group Server, delete UserList.bin.

 Note that this implementation supports server side directories.

  - User Interface

 Ensure the Group Server and File server Public keys are stored in the working directory of the ClientApp

 Start the GUI by running: 
 ```
 java -cp .:/path/to/BC/jar ClientAppGUI
 ```

 Start the command line UI by running: 
 ```
 java -cp .:/path/to/BC/jar ClientApp
 ```

 Follow the start up procedures entering the IP and port number for the File and Group servers.
 Then choose the user you want to access, the user must exist on the Group Server to log in so
 the first usage of the ClientApp will require the same admin user entered during the initial
 setup of the Group Server.
 
 Continue using the ClientApp by entering a menu item number then follow the further prompts.

 Only members of the admin group may create, or delete users.
 
 Creating a group makes you the sole owner of that group.
 
 Only owners and admins of groups may list members, add members, and delete the group.

