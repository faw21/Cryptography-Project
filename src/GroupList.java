/* This list represents the users on the server */
import java.util.*;


public class GroupList implements java.io.Serializable {

	/**
	 *
	 */
	private static final long serialVersionUID = 7600343803563417969L;
	private Hashtable<String, Group> list = new Hashtable<String, Group>();

	public synchronized boolean addGroup(String groupName, String ownerUsername)
	{
		Group newGroup = new Group(ownerUsername);
		if(list.put(groupName, newGroup) != null)
		{
			return false;
		}
		return true;
	}

	public synchronized void deleteGroup(String groupName)
	{
		list.remove(groupName);
	}

	public synchronized boolean checkGroup(String groupName)
	{
		if(list.containsKey(groupName))
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	public synchronized ArrayList<String> getGroupMembers(String groupName)
	{
		return list.get(groupName).getMembers();
	}

	public synchronized String getGroupOwner(String groupName)
	{
		return list.get(groupName).getOwner();
	}

	public synchronized void addMember(String user, String groupname)
	{
		list.get(groupname).addMember(user);
	}

	public synchronized void removeMember(String user, String groupname)
	{
		list.get(groupname).removeMember(user);
	}

	/*public synchronized void addOwnership(String user, String groupname)
	{
		list.get(groupname).addOwner(user);
	}*/

	public synchronized int removeOwnership(String user, String groupname)
	{
		if(list.get(groupname).getOwner().equals(user)){
			list.remove(groupname);
			return 0; //Success
		}
		return -1; //User wasn't owner ERR
	}


	class Group implements java.io.Serializable {

		/**
		 *
		 */
		private static final long serialVersionUID = -6699986336399821420L;
		//private ArrayList<String> permissions; //Access permissions for the members of this group (Future Use?)
		private String owner; //"Admin(s?)" of the group with access to add/remove members (& change permissions?)
		private ArrayList<String> members;

		public Group(String ownerUsername)
		{
			//permissions = new ArrayList<String>();
			//owners = new ArrayList<String>(); For multiple owners
			//owners.put(ownerUsername);

			owner = ownerUsername;
			members = new ArrayList<String>();
		}

		public ArrayList<String> getMembers()
		{
			return members;
		}

		public String getOwner()
		{
			return owner;
		}

		public void addMember(String username)
		{
			members.add(username);
		}

		public void removeMember(String username)
		{
			if(!members.isEmpty())
			{
				if(members.contains(username))
				{
					members.remove(members.indexOf(username));
				}
			}
		}

		/*public void removeOwner(String username)
		{
			//If user is the last owner - the group should be deleted
			//TODO: Ensure the above is enforced in GroupThread
			if(!owners.isEmpty())
			{
				if(owners.contains(username))
				{
					owners.remove(ownership.indexOf(username));
				}
			}
		}*/

	}

}
