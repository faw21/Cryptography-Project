import javax.swing.* ;
import java.awt.event.*;
import java.io.*;
import java.util.*;

public class ClientAppGUI extends JFrame{
	protected static UserToken token;
	protected static String username;
	protected static String password;
	private static String fip;
    private static String gip;
    private static int fport = 4321;
    private static int gport = 8765;
    protected static FileClient fclient;
    protected static GroupClient gclient;
    private JPanel panel;
    private JLabel fileIPLabel;
    private JTextField fileIPText;
    private JLabel filePortLabel;
    private JTextField filePortText;
    private JLabel groupIPLabel;
    private JTextField groupIPText;
    private JLabel groupPortLabel;
    private JTextField groupPortText;
    private JLabel userLabel;
    private JTextField userText;
    private JLabel passwordLabel;
    private JPasswordField passwordText;
    private JButton submitButton;

    public static void main(String[] args) {
        new ClientAppGUI();
    }
    public ClientAppGUI() {
        setDefaultLookAndFeelDecorated(true);

        setTitle("Super-fancy File System Interface");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        setSize(500,500);

        buildPanel();

        add(panel);

        setVisible(true);
    }

    private void buildPanel(){
        panel = new JPanel();
        panel.setLayout(null);

        fileIPLabel = new JLabel("File Server IP Address:");
        fileIPLabel.setBounds(10,20,160,25);
        panel.add(fileIPLabel);

        fileIPText = new JTextField(20);
        fileIPText.setBounds(180,20,165,25);
        panel.add(fileIPText);

        filePortLabel = new JLabel("File Server Port:");
        filePortLabel.setBounds(10,50,160,25);
        panel.add(filePortLabel);

        filePortText = new JTextField(20);
        filePortText.setBounds(180,50,165,25);
        panel.add(filePortText);

        groupIPLabel = new JLabel("Group Server IP Address:");
        groupIPLabel.setBounds(10,80,160,25);
        panel.add(groupIPLabel);

        groupIPText = new JTextField(20);
        groupIPText.setBounds(180,80,165,25);
        panel.add(groupIPText);

        groupPortLabel = new JLabel("Group Server Port:");
        groupPortLabel.setBounds(10,110,160,25);
        panel.add(groupPortLabel);

        groupPortText = new JTextField(20);
        groupPortText.setBounds(180,110,165,25);
        panel.add(groupPortText);

        userLabel = new JLabel("Username:");
        userLabel.setBounds(10,140,160,25);
        panel.add(userLabel);

        userText = new JTextField(20);
        userText.setBounds(180,140,165,25);
        panel.add(userText);

        passwordLabel = new JLabel("Password:");
        passwordLabel.setBounds(10,170,160,25);
        panel.add(passwordLabel);

        passwordText = new JPasswordField(20);
        passwordText.setBounds(180,170,165,25);
        panel.add(passwordText);

        submitButton = new JButton("login");
        submitButton.setBounds(10, 200, 80, 25);
        submitButton.addActionListener(new submitButtonListener());
        panel.add(submitButton);

    }

    private class submitButtonListener implements ActionListener{
        public void actionPerformed(ActionEvent event) {
            if (!filePortText.getText().equals("")){
                try {
                    fport = Integer.parseInt(filePortText.getText());
                } catch (Exception e){
                    JOptionPane.showMessageDialog(getComponent(0), "Invalid file server port number input!");
                    return;
                }
            }

            if (!groupPortText.getText().equals("")){
                try {
                    gport = Integer.parseInt(groupPortText.getText());
                } catch (Exception e){
                    JOptionPane.showMessageDialog(getComponent(0), "Invalid group server port number input!");
                    return;
                }
            }
            fip = fileIPText.getText();
            gip = groupIPText.getText();
            username = userText.getText();
            password = passwordText.getText();
            fclient = connectFileServer();
            gclient = connectGroupServer();
            if(fclient==null||gclient==null){
                JOptionPane.showMessageDialog(getComponent(0), "Connection failed, please try again.");
                return;
            }
            token = gclient.getToken();
            if (token == null) {
                JOptionPane.showMessageDialog(getComponent(0), "Wrong username/password, please try again.");
                fclient.disconnect();
                gclient.disconnect();
                return;
            }
            JOptionPane.showMessageDialog(getComponent(0), "Login successful!");
            setVisible(false);
            new OperationGUI();
        }

        

    }
    private FileClient connectFileServer() {
        FileClient rtn = new FileClient();
        boolean isconnected = false;
        try {
            isconnected = rtn.connect(fip, fport);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(getComponent(0), "Cannot connect to the server" + fip);
        }
        if(isconnected)
            return rtn;
        else{
            JOptionPane.showMessageDialog(getComponent(0), "File Server Connection Failed");
            return null;
        }

    }
    private GroupClient connectGroupServer() {
        GroupClient rtn = new GroupClient();
        boolean isconnected = false;
        try {
            isconnected = rtn.connect(gip, gport, username, password);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(getComponent(0), "Cannot connect to the server" + gip);
        }
        if(isconnected)
            return rtn;
        else{
            JOptionPane.showMessageDialog(getComponent(0), "Group Server Connection Failed");
            return null;
        }
    }
	// public static void main(String[] args){
	// 	frame = new JFrame("Super-fancy File System Interface");
 //        frame.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);

 //        frame.setSize(500,500);
 //        frame.setVisible(true);
 //        SwingUtilities.invokeLater(new Runnable() {
 //            @Override
 //            public void run() {
 //                ClientAppGUI ca = new ClientAppGUI();
 //                frame.setVisible(true);
 //            }
 //        });
	// }
	// private static ArrayList<Object> getServerInfoUsingGUI() {

 //        ArrayList<Object> serverInfo = new ArrayList<Object>();

 //        JFrame.setDefaultLookAndFeelDecorated(true);

 //        frame = new JFrame("Super-fancy File System Interface");
 //        frame.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);

 //        frame.setSize(500,500);

 //        JPanel panel = new JPanel();
 //        frame.add(panel);

 //        panel.setLayout(null);

 //        JLabel fileIPLabel = new JLabel("File Server IP Address:");
 //        fileIPLabel.setBounds(10,20,160,25);
 //        panel.add(fileIPLabel);

 //        JTextField fileIPText = new JTextField(20);
 //        fileIPText.setBounds(180,20,165,25);
 //        panel.add(fileIPText);

 //        JLabel filePortLabel = new JLabel("File Server Port:");
 //        filePortLabel.setBounds(10,50,160,25);
 //        panel.add(filePortLabel);

 //        JTextField filePortText = new JTextField(20);
 //        filePortText.setBounds(180,50,165,25);
 //        panel.add(filePortText);

 //        JLabel groupIPLabel = new JLabel("Group Server IP Address:");
 //        groupIPLabel.setBounds(10,80,160,25);
 //        panel.add(groupIPLabel);

 //        JTextField groupIPText = new JTextField(20);
 //        groupIPText.setBounds(180,80,165,25);
 //        panel.add(groupIPText);

 //        JLabel groupPortLabel = new JLabel("Group Server Port:");
 //        groupPortLabel.setBounds(10,110,160,25);
 //        panel.add(groupPortLabel);

 //        JTextField groupPortText = new JTextField(20);
 //        groupPortText.setBounds(180,110,165,25);
 //        panel.add(groupPortText);

 //        JLabel userLabel = new JLabel("Username:");
 //        userLabel.setBounds(10,140,160,25);
 //        panel.add(userLabel);

 //        JTextField userText = new JTextField(20);
 //        userText.setBounds(180,140,165,25);
 //        panel.add(userText);

 //        JLabel passwordLabel = new JLabel("Password:");
 //        passwordLabel.setBounds(10,170,160,25);
 //        panel.add(passwordLabel);

 //        JPasswordField passwordText = new JPasswordField(20);
 //        passwordText.setBounds(180,170,165,25);
 //        panel.add(passwordText);

 //        JButton submitButton = new JButton("login");
 //        submitButton.setBounds(10, 200, 80, 25);

 //        submitButton.addActionListener(new ActionListener() {
 //            public void actionPerformed(ActionEvent ae) {

 //                String a = groupIPText.getText();
 //        		System.out.println(a);
        		

 //        		if (!filePortText.getText().equals("")){
	// 				try {
	// 					fport = Integer.parseInt(filePortText.getText());
	// 				} catch (Exception e){
	// 					JOptionPane.showMessageDialog(frame.getComponent(0), "Invalid port number input!");
	// 					return;
	// 				}
	// 			}

	// 			if (!groupPortText.getText().equals("")){
	// 				try {
	// 					gport = Integer.parseInt(groupPortText.getText());
	// 				} catch (Exception e){
	// 					JOptionPane.showMessageDialog(frame.getComponent(0), "Invalid port number input!");
	// 					return;
	// 				}
	// 			}
 //        		fip = fileIPText.getText();
 //        		gip = groupIPText.getText();
 //                username = userText.getText();
 //                password = passwordText.getText();
 //        		doOp(serverInfo);
 //                fclient = connectFileServer();
 //                gclient = connectGroupServer();
 //                if(fclient!=null&&gclient!=null){
 //                    JOptionPane.showMessageDialog(frame.getComponent(0), "You have logged in!");
 //                }
 //            }
 //            private void doOp(ArrayList<Object> a){
 //            	System.out.println(a);
 //            }
 //            private FileClient connectFileServer() {
 //                FileClient rtn = new FileClient();
 //                boolean isconnected = false;
 //                try {
 //                    isconnected = rtn.connect(fip, fport);
 //                } catch (Exception e) {
 //                    JOptionPane.showMessageDialog(frame.getComponent(0), "Cannot connect to the server" + fip);
 //                }
 //                if(isconnected)
 //                    return rtn;
 //                else{
 //                    JOptionPane.showMessageDialog(frame.getComponent(0), "File Server Connection Failed");
 //                    return null;
 //                }

 //            }
 //            private GroupClient connectGroupServer() {
 //                GroupClient rtn = new GroupClient();
 //                boolean isconnected = false;
 //                try {
 //                    isconnected = rtn.connect(gip, gport, username, password);
 //                } catch (Exception e) {
 //                    JOptionPane.showMessageDialog(frame.getComponent(0), "Cannot connect to the server" + gip);
 //                }
 //                if(isconnected)
 //                    return rtn;
 //                else{
 //                    JOptionPane.showMessageDialog(frame.getComponent(0), "Group Server Connection Failed");
 //                    return null;
 //                }
 //            }

 //        });

 //        panel.add(submitButton);


 //        // 显示窗口
        
 //        //frame.setVisible(true);
 //        return serverInfo;
        
 //    }

 //    private static void placeComponents(JPanel panel) {

 //        /* 布局部分我们这边不多做介绍
 //         * 这边设置布局为 null
         
        
 //    }*/

}