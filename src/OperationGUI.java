import javax.swing.* ;
import java.awt.event.*;
import java.io.*;
import java.util.*;

public class OperationGUI extends JFrame{
    
    private JTabbedPane tabbedPane;
    private JComponent groupPanel;
    private JComponent filePanel;

    public OperationGUI(){

    	setDefaultLookAndFeelDecorated(true);

        setTitle("Super-fancy File System Interface");
        setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
        setSize(500,500);

        buildPanel();
        setVisible(true);
    }

    private void buildPanel(){
    	tabbedPane = new JTabbedPane();

        groupPanel = new GroupPanel();
        tabbedPane.addTab("Group Server", groupPanel);

        filePanel = new FilePanel();
        tabbedPane.addTab("File Server", filePanel);

        add(tabbedPane);

        setTitle("Super-fancy File System Interface");
        setSize(800, 400);
        setLocationRelativeTo(null);
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent event) {
                if (ClientAppGUI.gclient.isConnected())
                    ClientAppGUI.gclient.disconnect();
                if (ClientAppGUI.fclient.isConnected())
                    ClientAppGUI.fclient.disconnect();
                System.exit(0);
            }
        });
    }
}