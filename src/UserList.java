/* This list represents the users on the server */
import java.util.*;
import java.security.Key;


	public class UserList implements java.io.Serializable {

		/**
		 *
		 */
		private static final long serialVersionUID = 7600343803563417992L;
		private Hashtable<String, User> list = new Hashtable<String, User>();

		public synchronized void addUser(String username, Key _passwordKey)
		{
			User newUser = new User(_passwordKey);
			list.put(username, newUser);
		}

		public synchronized void deleteUser(String username)
		{
			list.remove(username);
		}

		public synchronized boolean checkUser(String username)
		{
			if(list.containsKey(username))
			{
				return true;
			}
			else
			{
				return false;
			}
		}

		public synchronized ArrayList<String> getUserGroups(String username)
		{
			return list.get(username).getGroups();
		}

		public synchronized ArrayList<String> getUserOwnership(String username)
		{
			return list.get(username).getOwnership();
		}

		public synchronized void addGroup(String user, String groupname)
		{
			list.get(user).addGroup(groupname);
		}

		public synchronized void removeGroup(String user, String groupname)
		{
			list.get(user).removeGroup(groupname);
		}

		public synchronized void addOwnership(String user, String groupname)
		{
			list.get(user).addOwnership(groupname);
			list.get(user).addGroup(groupname);
		}

		public synchronized void removeOwnership(String user, String groupname)
		{
			list.get(user).removeOwnership(groupname);
		}
		public synchronized Key getUserKey(String username)
		{
			return list.get(username).getKey();
		}
		public synchronized void setUserKey(String username, Key newKey)
		{
			if(!list.get(username).getKey().equals(newKey))
				list.get(username).setKey(newKey);
		}


	class User implements java.io.Serializable {

		/**
		 *
		 */
		private static final long serialVersionUID = -6699986336399821598L;
		private ArrayList<String> groups; //Groups they are in
		private ArrayList<String> ownership; //Groups they Own
		private Key passwordKey;

		public User(Key _passwordKey)
		{
			groups = new ArrayList<String>();
			ownership = new ArrayList<String>();
			passwordKey = _passwordKey;
		}

		public ArrayList<String> getGroups()
		{
			return groups;
		}

		public ArrayList<String> getOwnership()
		{
			return ownership;
		}

		public void addGroup(String group)
		{
			groups.add(group);
		}

		public void removeGroup(String group)
		{
			if(!groups.isEmpty())
			{
				if(groups.contains(group))
				{
					groups.remove(groups.indexOf(group));
				}
			}
		}

		public void addOwnership(String group)
		{
			ownership.add(group);
		}

		public void removeOwnership(String group)
		{
			if(!ownership.isEmpty())
			{
				if(ownership.contains(group))
				{
					ownership.remove(ownership.indexOf(group));
				}
			}
		}
		public Key getKey()
		{
			return passwordKey;
		}

		public void setKey(Key newKey)
		{
			passwordKey = newKey;
		}
	}

}
