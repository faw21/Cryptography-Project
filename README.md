# Cryptography Term Project
### Aaron Wu ###
### 2019 Fall ###
---

### Description ###
###### Background
In this project, we developed a group-based file sharing application that is secure against a number of different types of security threats. At a high level, our system will consist of three main components: a single group server, a collection of file servers, and some number of clients. 

The *group server* manages the users in the system and keeps track of the groups to which
each user belongs. Any number of *file servers* can be deployed throughout the network, and
will rely on the group server to provide each legitimate user with an authentication and
authorization token that answers the question *“Who are you, and what are you permitted
to do?”* Users within the system make use of a networked *client application* to log in to
the system and manage their groups (via the group server), as well as upload, download,
modify, and delete files stored in the system (via the file servers).

###### Trust Model
 - Group Server

The group server is **entirely trustworthy**. In the project, this means that the group server will only issue tokens to *properly authenticated* clients and will properly enforce the constraints on group creation, deletion, and management specified in previous phases of the project. The group server is not assumed to share secrets with the file servers in the system.

 - File Server

In the project, file servers will be assumed to be largely untrusted. In particular, file servers might leak files to unauthorized users or attempt to steal user tokens.

 - Customers

The clients are assumed to be not trustworthy. Specifically, clients may attempt to obtain tokens that belong to other users and/or modify the tokens issued to them by the group server to acquire additional permissions.

 - Other Principals

Assume that all communications in the system might be intercepted by an *active attacker* that can insert, reorder, replay, or modify messages.

###### Threat Model
- T1. Unauthorized Token Issurance

All clients are authenticated in a secure manner prior to issuing them tokens.

- T2. Token Modification/Forgery

Allow file servers (or anyone else) to determine whether a token is in fact valid and unmodified

- T3. Unauthorized File Server

If a user attempts to contact some server, *s*, then they actually connect to *s* and not some other server *s'*.

- T4. Information Leakage via Passive Monitoring

All communications between the client and server applications are hidden from outside observers. This will ensure that file contents remain private, and that tokens cannot be stolen in transit.

- T5. Message Reorder, Replay, or Modification

After connecting to a properly authenticated group server or file server, the messages sent between the user and the server might be reordered, saved for later replay, or otherwise modified by an active attacker. Users and servers have a means to detect message tampering, reordering, or replay. Upon detecting one of these exceptional conditions, it is permissible to terminate the client/server connection

- T6. File Leakage

Since file servers are untrusted, files may be leaked from the server to unauthorized principals. Thus, files leaked from the server are only readable by members of the appropriate group.

- T7. Token Theft

A file server may “steal” the token used by one of its clients and attempt to pass it off to another user. This project ensures that any stolen tokens are usable only on the server at which the theft took place (and are thus effectively useless, as this rogue file server could simply allow access without checking the token).

### Compile and Usage ###
Once inside src/ folder,

###### COMPILE:
```
javac -cp path/to/bouncy/castle/jar *.java
```



###### USAGE:

***To start Group Server:***
 ```
 java -cp .:/path/to/BC/jar RunGroupServer [(optional) port number]
 ```
 
- When the group server is first started, there are no users or groups. Since
 there must be an administer of the system, the user is prompted via the console
 to enter a username. This name becomes the first user and is a member of the
 ADMIN group.  Also, no groups exist.  The group server will by default
 run on port 8765, but a custom port can be passed as the first command line
 argument.

***To start the File Server:***

 Ensure the Group Server public key is in the same directory as the stored File server
 
 ```
 java RunFileServer -cp .:/path/to/BC/jar [(optional) port number]
 ```
 
 - The file server will create a shared_files inside the working directory if one
 does not exist. The file server is now online.  The file server will by default
 run on port 4321, but a custom port can be passed as the first command line
 argument.

 - To reset the File server completely, delete FileList.bin and the shared_files
 directory.
 
 - To reset the Group Server, delete UserList.bin.

 - Note that this implementation supports server side directories.

***User Interface***

 Ensure the Group Server and File server Public keys are stored in the working directory of the ClientApp

 Start the **GUI** by running: 
 ```
 java -cp .:/path/to/BC/jar ClientAppGUI
 ```

 Start the **command line UI** by running: 
 ```
 java -cp .:/path/to/BC/jar ClientApp
 ```

 - Follow the start up procedures entering the IP and port number for the File and Group servers.
 Then choose the user you want to access, the user must exist on the Group Server to log in so
 the first usage of the ClientApp will require the same admin user entered during the initial
 setup of the Group Server.
 
 - Continue using the ClientApp by entering a menu item number then follow the further prompts.

 - Only members of the admin group may create, or delete users.
 
 - Creating a group makes you the sole owner of that group.
 
 - Only owners and admins of groups may list members, add members, and delete the group.

