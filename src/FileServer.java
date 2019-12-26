/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;

public class FileServer extends Server {

    public static final int SERVER_PORT = 4321;
    public static FileList fileList;

    public FileServer() {
        super(SERVER_PORT, "FilePile");
    }

    public FileServer(int _port) {
        super(_port, "FilePile");
    }

    public void start() {
        String fileFile = "FileList.bin";
        // filenames for public key and private keys
        String publicKeyFilename = "file_public.key";
        String privateKeyFilename = "file_private.key";
        String groupKeyFilename = "group_public.key";
        ObjectInputStream fileStream;

        //This runs a thread that saves the lists on program exit
        Runtime runtime = Runtime.getRuntime();
        Thread catchExit = new Thread(new ShutDownListenerFS());
        runtime.addShutdownHook(catchExit);

        // test whether key exist, if not, create key pair
        try {
            FileInputStream pubkis = new FileInputStream(publicKeyFilename);
            FileInputStream prikis = new FileInputStream(privateKeyFilename);
            pubkis.close();
            prikis.close();
        } catch (FileNotFoundException e) {
            System.out.println("Keys do not exist, creating key pair...");
            SecurityLib lib = SecurityLib.getInstance();
            KeyPair keyPair = lib.generateKeyPair();
            lib.writeKeyToFile(keyPair.getPublic(), publicKeyFilename);
            lib.writeKeyToFile(keyPair.getPrivate(), privateKeyFilename);
        } catch (IOException e) {
            System.out.println("Can't close file input streams");
        }

        // test whether group server public key file exists, if not, existing
        try {
            FileInputStream group_pubkis = new FileInputStream(groupKeyFilename);
            group_pubkis.close();
        } catch (FileNotFoundException e) {
            System.out.println("Server public key file does not exist, can not verify signature of token, existing...");
            System.exit(-1);
        } catch (IOException e) {
            System.out.println("Can't close file input streams");
        }

        //Open user file to get user list
        try
        {
            FileInputStream fis = new FileInputStream(fileFile);
            fileStream = new ObjectInputStream(fis);
            fileList = (FileList)fileStream.readObject();
        }
        catch(FileNotFoundException e)
        {
            System.out.println("FileList Does Not Exist. Creating FileList...");
            System.out.println("Key files do not exist. Creating keys...");


            fileList = new FileList();

        }
        catch(IOException e)
        {
            System.out.println("Error reading from FileList file");
            System.exit(-1);
        }
        catch(ClassNotFoundException e)
        {
            System.out.println("Error reading from FileList file");
            System.exit(-1);
        }

        // create the file directory if not found
        File file = new File("shared_files");
        if (file.mkdir()) { // try to make the directory, if success, then it doesn't exist
            System.out.println("Created new shared_files directory");
        }
        else if (file.exists()){ // if the directory exists already, just do nothing
            System.out.println("Found shared_files directory");
        }
        else {
            System.out.println("Error creating shared_files directory");
        }


        //Autosave Daemon. Saves lists every 5 minutes
        AutoSaveFS aSave = new AutoSaveFS();
        aSave.setDaemon(true);
        aSave.start();


        boolean running = true;

        try
        {
            final ServerSocket serverSock = new ServerSocket(port);
            System.out.printf("%s up and running\n", this.getClass().getName());

            Socket sock = null;
            Thread thread = null;

            while(running)
            {
                sock = serverSock.accept(); // accept a request and build the socket
                thread = new FileThread(sock); // start a new thread to handle that request
                thread.start();
            }

            System.out.printf("%s shut down\n", this.getClass().getName());
        }
        catch(Exception e)
        {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}

//This thread saves user and group lists
class ShutDownListenerFS implements Runnable
{
    public void run()
    {
        System.out.println("Shutting down server");
        ObjectOutputStream outStream;

        // when this thread is run(I think while shutting down?)
        // it will write the FileServer.fileList(an object) to FileList.bin
        try
        {
            outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
            outStream.writeObject(FileServer.fileList);
        }
        catch(Exception e)
        {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}

class AutoSaveFS extends Thread
{
    public void run()
    {
        // just like the last thread, but this one run while the server is running
        // and it saves the fileList object to FileList.bin file every 5 minutes
        do
        {
            try
            {
                Thread.sleep(300000); //Save group and user lists every 5 minutes
                System.out.println("Autosave file list...");
                ObjectOutputStream outStream;
                try
                {
                    outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
                    outStream.writeObject(FileServer.fileList);
                }
                catch(Exception e)
                {
                    System.err.println("Error: " + e.getMessage());
                    e.printStackTrace(System.err);
                }

            }
            catch(Exception e)
            {
                System.out.println("Autosave Interrupted");
            }
        }while(true);
    }
}
