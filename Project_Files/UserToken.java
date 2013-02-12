import java.util.List;

public class UserToken implements UserTokenInterface, java.io.Serializable
{
	private String issuer; 
	private String subject; 
    private List<String> groups;

	public UserToken(String Issuer, String Subject)
	{
		issuer = Issuer; 
		subject = Subject; 
	}

    public UserToken(String Issuer, String Subject, List<String> Groups)
    {
        issuer = Issuer; 
        subject = Subject; 
        groups = Groups;
    }

    public String getIssuer()
    {
    	return issuer; 
    }

    public String getSubject()
    {
    	return subject;
    }

    public List<String> getGroups()
    {
        return groups; 
    }

    public Boolean addGroup(String group)
    {
        return groups.add(group);
    }

    public Boolean inGroup(String group)
    {
        return groups.contains(group);
    }

    public Boolean removeGroup(String group)
    {
        return groups.remove(group);
    }

    public int groupCount()
    {
        return groups.size();
    }

    public void clearGroups()
    {
        groups.clear();
    }


}
