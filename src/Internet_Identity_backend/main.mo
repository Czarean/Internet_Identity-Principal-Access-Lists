//Version 3.0 Working Code!
//Principals Access List Working Code
//This implementation ensures that only authorized principals listed in the ACL HashMap can call the Authgreet function.
//Also only authorized Principals Can Add more Principals to the Access List
//**On my next code I should add the default configuration so the Canister Itself can add and remove Principal IDs by default as a Fallback 
//**directly from the DFX Shell with DFX Commands, this is just In case the current Admins loose access, acting as a fallback
//**Its easy to do this you just need to uncomment Line 53 and you are good to go, the explanation is there as well. Hope this helps!

import Principal "mo:base/Principal";
import Text "mo:base/Text";
import HashMap "mo:base/HashMap";

actor myactorname{

  // Access List Hashmap Type
  type PrincipalSet = Text;

  // Initialize the ACL
  let acl = HashMap.HashMap<Text, PrincipalSet>(0, Text.equal, Text.hash);

//The ACL hashmap (acl) is initialized with an anonymous principal (anonymousPid).
  let anonymousPid: PrincipalSet = "2vxsx-fae";
  acl.put("2vxsx-fae" , anonymousPid);

//Replace the Principal, if you want to hardcode a Principal to be automatically added onto the ACL Hashmap. I.E you can use the Canister Principal to allow your Canister to call the Function from the DFX command Line.
  let testPid: PrincipalSet = "6m3mt-saeju-ijgiz-2etk7-75qpa-edcqd-ygqdh-m44fd-ihups-ksm44-cqe";
  acl.put("6m3mt-saeju-ijgiz-2etk7-75qpa-edcqd-ygqdh-m44fd-ihups-ksm44-cqe" , testPid);

//whoAmI Function: This returns the caller's Principal which can be useful for debugging or identification.
  public query msg func whoAmI() : async Principal {
    return msg.caller;
  };

//greet Function : A simple greeting function that is not restricted.
  public query func greet(name: Text) : async Text {
    return "Hello, " # name # "!";
  };

//(*Restricted Function*) that checks the caller against the "acl.HashMap" for authorization
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

  // (*Restricted Function*) to add Principals to the acl.HashMap 
  public shared(msg) func addPrincipal(id: Text, newPrincipal: Text): async Text { // Finally found the sintax for the update function here: https://internetcomputer.org/docs/current/motoko/main/writing-motoko/caller-id#:~:text=public%20shared(msg)%20func%20inc()%20%3A%20async%20()%20%7B Adding Access Control https://internetcomputer.org/docs/current/motoko/main/writing-motoko/caller-id
 //   let callerPrincipal = Principal.toText(Principal.fromActor(myactorname)); // Get the caller's principal as text //*** Principal.fromActor(myactorname) returns the principal of the canister, not the caller. We should use msg.caller to get the caller's principal in update functions. ***
    let callerPrincipal = Principal.toText(msg.caller); // Get the caller's principal as text // FYI on update Functions the sintax is: public shared(msg) func myFunction(i: Text, n: Text): async(){ 
    switch (acl.get(callerPrincipal)) { // Check if the caller is in the ACL
      case (?principalSet) { // If the caller is authorized, add the new principal to the ACL
        acl.put(id, newPrincipal);
        return "The Principal ID: " # newPrincipal # " has been successfully added to the Access List";
      };
      case (null) { // If the caller is not authorized, return an error message
        return "You are not authorized to add principals to the Access List";
      }
    }
  };
}
