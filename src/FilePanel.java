import javax.swing.* ;
import java.awt.event.*;
import java.io.*;
import java.util.*;

public class FilePanel extends JPanel{
    
    private JPanel groupPanel;
    private JPanel filePanel;
    private JPanel operationPanel;
    private JButton upFileBtn;
    private JButton downFileBtn;
    private JButton deleteFileBtn;
    private JButton lFileBtn;//list file button
    private JButton lGroupBtn;//list group button

    private JList groupList;
    private JList fileList;

    @SuppressWarnings("unchecked")
    private DefaultListModel groupListModel;
    @SuppressWarnings("unchecked")
    private DefaultListModel fileListModel;

    @SuppressWarnings("unchecked")
    public FilePanel(){

        JSplitPane contentPanel = new JSplitPane();

        groupListModel = new DefaultListModel();
        groupList = new JList(groupListModel);
        groupList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane groupListPane = new JScrollPane(groupList);

        fileListModel = new DefaultListModel();
        fileList = new JList(fileListModel);
        fileList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane fileListPane = new JScrollPane(fileList);

        contentPanel.setLeftComponent(buildLeft(groupList, fileList));

        contentPanel.setRightComponent(buildRight(groupListPane, fileListPane));

        add(contentPanel);
    }

    private JSplitPane buildRight(final JScrollPane groupListPane, final JScrollPane fileListPane) {
        JSplitPane panel = new JSplitPane();

        // Group list panel: label + list
        groupPanel = new JPanel();
        groupPanel.add(new JLabel("My Groups"));
        groupPanel.add(groupListPane);
        groupPanel.setLayout(new BoxLayout(groupPanel, BoxLayout.Y_AXIS));

        // file list panel: label + list
        filePanel = new JPanel();
        filePanel.add(new JLabel("Files"));
        filePanel.add(fileListPane);
        filePanel.setLayout(new BoxLayout(filePanel, BoxLayout.Y_AXIS));

        panel.setLeftComponent(groupPanel);
        panel.setRightComponent(filePanel);

        return panel;
    }

    private JPanel buildLeft(final JList groupList, final JList fileList) {

        operationPanel = new JPanel();
        operationPanel.add(new JLabel("Operations:"));

        iniButtons();

        upFileBtn.addActionListener(new uploadFile_Listener());
        downFileBtn.addActionListener(new downloadFile_Listener());
        deleteFileBtn.addActionListener(new deleteFile_Listener());
        lFileBtn.addActionListener(new listFile_Listener());
        lGroupBtn.addActionListener(new listGroup_Listener());
        operationPanel.add(upFileBtn);
		operationPanel.add(downFileBtn);
		operationPanel.add(deleteFileBtn);
		operationPanel.add(lFileBtn);
		operationPanel.add(lGroupBtn);

        operationPanel.setLayout(new BoxLayout(operationPanel, BoxLayout.Y_AXIS));

        return operationPanel;
    }

    @SuppressWarnings("unchecked")
    private class uploadFile_Listener implements ActionListener{
    	public void actionPerformed(ActionEvent event){
    		int index = groupList.getSelectedIndex();
    		if (index != -1) {
                String group = groupListModel.get(index).toString();
                String sourceFile = askForInput("Enter the name of the file you want to upload:");
                String destFile = askForInput("Enter the file name that appears on the server:");
                boolean result = ClientAppGUI.fclient.upload(sourceFile, destFile, group, ClientAppGUI.token);
                if(result){
                	JOptionPane.showMessageDialog(null, "File " + destFile + " successfully uploaded to group " + group + ".");
                	fileListModel.removeAllElements();
                }
                else JOptionPane.showMessageDialog(null, "Error in uploading file " + destFile + ".");
            }
            else JOptionPane.showMessageDialog(null, "Select a group.");
    	}
    }

    @SuppressWarnings("unchecked")
    private class downloadFile_Listener implements ActionListener{
    	public void actionPerformed(ActionEvent event){
    		int index = fileList.getSelectedIndex();
    		if (index != -1) {
                String sourceFile = fileListModel.get(index).toString();
                String destFile = askForInput("Enter the file name that appears on the local:");
                boolean result = ClientAppGUI.fclient.download(sourceFile, destFile, ClientAppGUI.token);
                if(result){
                	JOptionPane.showMessageDialog(null, "File " + destFile + " successfully downloaded.");
                }
                else JOptionPane.showMessageDialog(null, "Error in downloading file " + destFile + ".");
            }
            else JOptionPane.showMessageDialog(null, "Select a file.");
    	}
    }

    @SuppressWarnings("unchecked")
    private class deleteFile_Listener implements ActionListener{
    	public void actionPerformed(ActionEvent event){
    		int index = fileList.getSelectedIndex();
    		if (index != -1) {
                String filename = fileListModel.get(index).toString();
                int choice = JOptionPane.showConfirmDialog(null, "Delete file " + filename + "?", "WARNING", JOptionPane.YES_NO_OPTION);
                if (choice == JOptionPane.YES_OPTION)
	                if(ClientAppGUI.fclient.delete(filename, ClientAppGUI.token)){
	                	List<String> files = ClientAppGUI.fclient.listFiles(ClientAppGUI.token);
	            		fileListModel.removeAllElements();
	            		groupListModel.removeAllElements();

	            		for (String file : files) 
	                		fileListModel.addElement(file);

	                	JOptionPane.showMessageDialog(null, "File " + filename + " successfully deleted.");
	                }
	                else JOptionPane.showMessageDialog(null, "Error in deleting file " + filename + ".");
            }
            else JOptionPane.showMessageDialog(null, "Select a file.");
    	}
    }

    @SuppressWarnings("unchecked")
    private class listFile_Listener implements ActionListener{
        public void actionPerformed(ActionEvent event){
            List<String> files = ClientAppGUI.fclient.listFiles(ClientAppGUI.token);
            fileListModel.removeAllElements();
            groupListModel.removeAllElements();
            for (String file : files) 
                fileListModel.addElement(file);
        }
    }

    @SuppressWarnings("unchecked")
    private class listGroup_Listener implements ActionListener{
        public void actionPerformed(ActionEvent event){
            ClientAppGUI.token = ClientAppGUI.gclient.getToken();
            List<String> groups = ClientAppGUI.token.getGroups();
            fileListModel.removeAllElements();
            groupListModel.removeAllElements();
            for (String group : groups) 
                groupListModel.addElement(group);
        }
    }

    private String askForInput(String prompt){
        String input = JOptionPane.showInputDialog(prompt);
        
        while (input==null){
            JOptionPane.showMessageDialog(null, "Cannot be empty!");
            input = JOptionPane.showInputDialog(prompt);
        }

        return input;
    }

    private void iniButtons(){
        upFileBtn = new JButton("Upload File");
        downFileBtn = new JButton("Download File");
        deleteFileBtn = new JButton("Delete File");
        lFileBtn = new JButton("List Files");
        lGroupBtn = new JButton("List Groups");
    }
}