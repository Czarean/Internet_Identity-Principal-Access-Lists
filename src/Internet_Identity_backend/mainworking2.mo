//Version 2.0 Working Code!
//This implementation ensures that only authorized principals listed in the ACL HashMap can call the Authgreet function.
//Additionally there is a function to add principasl to the ACL HASHMAP, however it can be called by anyone!
//To be implemented On the next version: it can only be called by the Anonymous Principal, or any other Principal added to the ACL HASHMAP

import Principal "mo:base/Principal";
import Text "mo:base/Text";
import HashMap "mo:base/HashMap";

actor {

  // Access List Hashmap Type
  type PrincipalSet = Text;

  // Initialize the ACL
  let acl = HashMap.HashMap<Text, PrincipalSet>(0, Text.equal, Text.hash);

//The ACL hashmap (acl) is initialized with an anonymous principal (anonymousPid).
  let anonymousPid: PrincipalSet = "2vxsx-fae";
  acl.put("2vxsx-fae", anonymousPid);

//whoAmI Function: This returns the caller's Principal which can be useful for debugging or identification.
  public query msg func whoAmI() : async Principal {
    return msg.caller;
  };

//greet Function: A simple greeting function that is not restricted.
  public query func greet(name: Text) : async Text {
    return "Hello, " # name # "!";
  };

//Restricted Function that checks the caller against the "acl.HashMap" for authorization
    public query msg func Authgreet(name: Text): async Text {
    let callerPrincipal = Principal.toText(msg.caller); // The msg.caller is converted to text format using Principal.toText(msg.caller).
    switch (acl.get(callerPrincipal)) { //The function checks if the caller's principal exists in the ACL using acl.get(callerPrincipal).
        case (?principalSet) { // If the principal is found (?principalSet), it returns a greeting.
            return "Hello, " # name # "!";
        };
        case (null) { // If the principal is not found (null), it returns "not authorized".
            return "not authorized";
        }
    }
    };

//Function to add Principals to the acl.HashMap (Not Restricted)
    public func addPrincipal(id: Text, newPrincipal: Text): async Text {
        let anonymousPid: PrincipalSet = newPrincipal;         
        acl.put(id, newPrincipal);
        return "The Princicipal ID: "  # newPrincipal # " Has been successfully added to the Access List" 

    };

}