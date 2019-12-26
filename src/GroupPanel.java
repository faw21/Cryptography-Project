import javax.swing.* ;
import java.awt.event.*;
import java.io.*;
import java.util.*;

public class GroupPanel extends JPanel{

    private JPanel groupPanel;
    private JPanel memberPanel;
    private JPanel operationPanel;
    private JButton cUserBtn;
    private JButton dUserBtn;
    private JButton addUserToGroupBtn;
    private JButton rmvUserFromGroupBtn;
    private JButton cGroupBtn;
    private JButton dGroupBtn;
    private JButton lMemberBtn;//list member button
    private JButton lGroupBtn;//list group button

    private JList groupList;
    private JList memberList;

    @SuppressWarnings("unchecked")
    private DefaultListModel groupListModel;
    @SuppressWarnings("unchecked")
    private DefaultListModel memberListModel;

    @SuppressWarnings("unchecked")
    public GroupPanel(){
        JSplitPane contentPanel = new JSplitPane();

        groupListModel = new DefaultListModel();
        groupList = new JList(groupListModel);
        groupList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane groupListPane = new JScrollPane(groupList);

        memberListModel = new DefaultListModel();
        memberList = new JList(memberListModel);
        memberList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane memberListPane = new JScrollPane(memberList);

        contentPanel.setLeftComponent(buildLeft(groupList, memberList));

        contentPanel.setRightComponent(buildRight(groupListPane, memberListPane));

        add(contentPanel);
    }

    private JSplitPane buildRight(final JScrollPane groupListPane, final JScrollPane memberListPane) {
        JSplitPane panel = new JSplitPane();

        // Group list panel: label + list
        groupPanel = new JPanel();
        groupPanel.add(new JLabel("My Groups"));
        groupPanel.add(groupListPane);
        groupPanel.setLayout(new BoxLayout(groupPanel, BoxLayout.Y_AXIS));

        // Members list panel: label + list
        memberPanel = new JPanel();
        memberPanel.add(new JLabel("Members"));
        memberPanel.add(memberListPane);
        memberPanel.setLayout(new BoxLayout(memberPanel, BoxLayout.Y_AXIS));

        panel.setLeftComponent(groupPanel);
        panel.setRightComponent(memberPanel);

        return panel;
    }

    private JPanel buildLeft(final JList groupList, final JList memberList) {

        operationPanel = new JPanel();
        operationPanel.add(new JLabel("Operations:"));

        iniButtons();
        cUserBtn.addActionListener(new createUser_Listener());
        dUserBtn.addActionListener(new deleteUser_Listener());
        cGroupBtn.addActionListener(new createGroup_Listener());
        dGroupBtn.addActionListener(new deleteGroup_Listener());
        addUserToGroupBtn.addActionListener(new addUserToGroup_Listener());
        rmvUserFromGroupBtn.addActionListener(new removeUserFromGroup_Listener());
        lMemberBtn.addActionListener(new listMember_Listener());
        lGroupBtn.addActionListener(new listGroup_Listener());
        operationPanel.add(cUserBtn);
        operationPanel.add(dUserBtn);
        operationPanel.add(addUserToGroupBtn);
        operationPanel.add(rmvUserFromGroupBtn);
        operationPanel.add(cGroupBtn);
        operationPanel.add(dGroupBtn);
        operationPanel.add(lMemberBtn);
        operationPanel.add(lGroupBtn);

        operationPanel.setLayout(new BoxLayout(operationPanel, BoxLayout.Y_AXIS));

        return operationPanel;
    }

    private class createUser_Listener implements ActionListener{
        public void actionPerformed(ActionEvent event){
            String newUsername = askForInput("New username:");
            String newPassword = askForInput("Password (minimum 8 characters):");
            while(newPassword.length()<8){
                newPassword = askForInput("Password has to be at least 8 characters! Re-enter):");
            }
            boolean result = ClientAppGUI.gclient.createUser(newUsername, newPassword, ClientAppGUI.token);
            if (result) {
                JOptionPane.showMessageDialog(null, "User: " + newUsername + " successfully created!");
            }
            else JOptionPane.showMessageDialog(null, "Error in creating user " + newUsername);
        }
    }

    private class deleteUser_Listener implements ActionListener{
        public void actionPerformed(ActionEvent event){
            String username = askForInput("Enter the username you want to delete:");
            boolean result = ClientAppGUI.gclient.deleteUser(username, ClientAppGUI.token);
            if (result) {
                JOptionPane.showMessageDialog(null, "User: " + username + " successfully deleted!");
            }
            else JOptionPane.showMessageDialog(null, "Error in creating user " + username);
        }
    }

    @SuppressWarnings("unchecked")
    private class createGroup_Listener implements ActionListener{
        public void actionPerformed(ActionEvent event){
            String group = askForInput("Enter the new group's name:");
            boolean result = ClientAppGUI.gclient.createGroup(group, ClientAppGUI.token);
            if (result) {
                JOptionPane.showMessageDialog(null, "Group: " + group + " successfully created!");
                groupListModel.addElement(group);
                memberListModel.removeAllElements();
            }
            else JOptionPane.showMessageDialog(null, "Error in creating group " + group);
            ClientAppGUI.token = ClientAppGUI.gclient.getToken();
        }
    }

    @SuppressWarnings("unchecked")
    private class deleteGroup_Listener implements ActionListener{
        public void actionPerformed(ActionEvent event){
            int index = groupList.getSelectedIndex();
            if (index != -1) {
                String group = groupListModel.get(index).toString();
                int choice = JOptionPane.showConfirmDialog(null, "Delete group " + group + "?", "WARNING", JOptionPane.YES_NO_OPTION);
                if (choice == JOptionPane.YES_OPTION)
                    if (ClientAppGUI.gclient.deleteGroup(group, ClientAppGUI.token)) {
                        groupListModel.remove(index);
                        memberListModel.removeAllElements();
                    } else
                        JOptionPane.showMessageDialog(null, "Error in deleting group " + group);
            } else
                JOptionPane.showMessageDialog(null, "Select a group");
            
            ClientAppGUI.token = ClientAppGUI.gclient.getToken();
        }
    }

    @SuppressWarnings("unchecked")
    private class addUserToGroup_Listener implements ActionListener{
        public void actionPerformed(ActionEvent event){
            int index = groupList.getSelectedIndex();
            if (index != -1) {
                String group = groupListModel.get(index).toString();
                String username = askForInput("Enter the username you want to add to group " + group + " :");

                boolean result = ClientAppGUI.gclient.addUserToGroup(username, group, ClientAppGUI.token);
                if (result) {
                    JOptionPane.showMessageDialog(null, "User " + username + " successfully added to group " + group);
                    List<String> members = (List<String>) ClientAppGUI.gclient.listMembers(group, ClientAppGUI.token);
                    memberListModel.removeAllElements();
                    for (String member : members) 
                        memberListModel.addElement(member);
                }
                else JOptionPane.showMessageDialog(null, "Error in adding user.");
                

            } else
                JOptionPane.showMessageDialog(null, "Select a group");
            
            ClientAppGUI.token = ClientAppGUI.gclient.getToken();
        }
    }

    @SuppressWarnings("unchecked")
    private class removeUserFromGroup_Listener implements ActionListener{
        public void actionPerformed(ActionEvent event){
            int groupIndex = groupList.getSelectedIndex();
            int memberIndex = memberList.getSelectedIndex();
            if (groupIndex != -1 && memberIndex != -1) {
                String group = groupListModel.get(groupIndex).toString();
                String username = memberListModel.get(memberIndex).toString();

                boolean result = ClientAppGUI.gclient.deleteUserFromGroup(username, group, ClientAppGUI.token);
                if (result) {
                    JOptionPane.showMessageDialog(null, "User " + username + " successfully removed from group " + group);
                    List<String> members = (List<String>) ClientAppGUI.gclient.listMembers(group, ClientAppGUI.token);
                    memberListModel.removeAllElements();
                    for (String member : members) 
                        memberListModel.addElement(member);
                }
                else JOptionPane.showMessageDialog(null, "Error in removing user.");

            } else JOptionPane.showMessageDialog(null, "Select a group and a user");
            
            ClientAppGUI.token = ClientAppGUI.gclient.getToken();
        }
    }

    @SuppressWarnings("unchecked")
    private class listMember_Listener implements ActionListener{
        public void actionPerformed(ActionEvent event){
            int index = groupList.getSelectedIndex();
            if(index!=-1){
                String group = groupListModel.get(index).toString();
                List<String> members = (List<String>) ClientAppGUI.gclient.listMembers(group, ClientAppGUI.token);
                memberListModel.removeAllElements();
                for (String member : members) 
                    memberListModel.addElement(member);
            }
            else JOptionPane.showMessageDialog(null, "Select a group");
        }
    }

    @SuppressWarnings("unchecked")
    private class listGroup_Listener implements ActionListener{
        public void actionPerformed(ActionEvent event){
            ClientAppGUI.token = ClientAppGUI.gclient.getToken();
            List<String> groups = ClientAppGUI.token.getGroups();
            memberListModel.removeAllElements();
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
        cUserBtn = new JButton("Create User");
        dUserBtn = new JButton("Delete User");
        addUserToGroupBtn = new JButton("Add User");
        rmvUserFromGroupBtn = new JButton("Remove User");
        cGroupBtn = new JButton("Create Group");
        dGroupBtn = new JButton("Delete Group");
        lMemberBtn = new JButton("List Members");
        lGroupBtn = new JButton("List Groups");
    }


}