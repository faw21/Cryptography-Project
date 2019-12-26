// todo: try/catch when creating the object and convert strings when necessary, because the message can be wrong(not well formed)
//import org.json.JSONObject;
//import org.json.JSONArray;
import java.util.List;
import java.util.ArrayList;
import java.io.Serializable;

public class OurUserToken implements UserToken, Serializable {

  //private JSONObject tokenJsonObject;
  private String issuer;
  private String subject;
  private List<String> groups;

  // create the token object from a json string
  /*public OurUserToken(String json_str) {
    this.tokenJsonObject = new JSONObject(json_str);
    this.issuer = this.tokenJsonObject.get("issuer").toString();
    this.subject = this.tokenJsonObject.get("subject").toString();
    JSONArray ja = this.tokenJsonObject.getJSONArray("groups");
    this.groups = new ArrayList<String>();
    for (int i=0; i<ja.length(); i++) {
      this.groups.add(ja.getString(i));
    }
  } */

  // make the the token string to send through the internet
  // @issuer: the issuer of the token
  // @subject: the one who require the token
  // @groups: the string array with groups the subject/user has access to
  // I am not sure yet the json string returned by the method words when passed through the internet
  // but there are two ways, hopefully one of them works
  public OurUserToken(String issuer, String subject, List<String> groups) {
    this.issuer = issuer;
    this.subject = subject;
    this.groups = groups;
    //this.tokenJsonObject = new JSONObject();
    //this.tokenJsonObject.put("issuer", issuer);
    //this.tokenJsonObject.put("subject", subject);
    //this.tokenJsonObject.put("groups", groups);
  }

  // get the issuer(group server) from the json message
  public String getIssuer() {
    return this.issuer;
  }

  // get the subject(user) from the json message
  public String getSubject() {
    return this.subject;
  }

  // get the group information from the json message
  public List<String> getGroups() {
    return this.groups;
  }

  public String getFilePubKey(){return null;}

  // for debug using
  public String toString() {
    return null;
    //return this.tokenJsonObject.toString();
    // return JSONObject.quote(this.tokenJsonObject.toString());
  }

}
