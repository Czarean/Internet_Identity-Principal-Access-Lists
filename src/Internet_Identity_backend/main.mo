//Version 3.0 Working Code!
//Principals Access List Working Code
//This implementation ensures that only authorized principals listed in the ACL HashMap can call the Authgreet function.
//only authorized Principals Can Add more Principals to the Access List
//There is a fallback mecnahnism in place, where you hardcode your deployer canister Principal ID, this is done so you can add Principals from your deployer canister using the dfx command:  $dfx canister call canister_name addPrincipal '( "exampleId", "examplePrincipal" )'
//This is done to avoid a potential scenario where all your allowed Principals on the access list, lost access or forget their credentials. So you will be able to add new Internet Identities with no problem at all.

import Principal "mo:base/Principal";
import Text "mo:base/Text";
import HashMap "mo:base/HashMap";

actor myactorname{

  // Access List Hashmap Type
  type PrincipalSet = Text;

  // Initialize the ACL
  let acl = HashMap.HashMap<Text, PrincipalSet>(0, Text.equal, Text.hash);

//The ACL hashmap (acl) is initialized with an anonymous principal (anonymousPid).
//Note: remove the below two lines of code (23-24) before you deploy to production as they are only for testing on the replica test enviroment.
  let anonymousPid: PrincipalSet = "2vxsx-fae";
  acl.put("2vxsx-fae" , anonymousPid);

//Replace the Principal, if you want to hardcode a Principal to be automatically added onto the ACL Hashmap. 
//Fallback: As a security and Anti-lock mechanism, you should whitelist the deployer canister PID as shown in lines below
//Doing this will allow your deployer canister to call all the functions so you can add/delete PIDs from the access list.
//To get your deployer canister ID, use the dfx command: $dfx identity get-principal
//And replace it on the below two lines of code: Once you do this, you do not have to worry if All Principals on the Access List stop having access because they forgot their credentials or whatever, you can just simply direct your Admins to create new Internet Identities, and then you can add the new Principal IDs to the Access list via the DFX Command: $dfx canister call canister_name addPrincipal '( "exampleId", "examplePrincipal" )'
  let canisterIdPid: PrincipalSet = "xmrjp-ypfwv-gzymg-q35zv-tphew-xq6l7-k6kp3-nprrw-pmd4q-6vk2s-oqe";
  acl.put("xmrjp-ypfwv-gzymg-q35zv-tphew-xq6l7-k6kp3-nprrw-pmd4q-6vk2s-oqe" , canisterIdPid);

//whoAmI Function: This returns the caller's Principal which can be useful for debugging or identification.
  public query msg func whoAmI() : async Principal {
    return msg.caller;
  };

//greet Function : A simple greeting function that is not restricted.
  public query func greet(name: Text) : async Text {
    return "Hello, " # name # "!";
  };

// *Restricted Function* that checks the caller against the "acl.HashMap" for authorization, if the PID is allowed it will to proceed the function.
    public query msg func Authgreet(name: Text): async Text {
    let callerPrincipal = Principal.toText(msg.caller); // The msg.caller is converted to text format using Principal.toText(msg.caller).
    switch (acl.get(callerPrincipal)) { //The function checks if the caller's principal exists in the ACL using acl.get(callerPrincipal).
        case (?principalSet) { // If the principal is found (?principalSet), it returns a greeting.
            return "Hello, " # name # "!";
        };
        case (null) { 
            return "not authorized";
        }
    }
    };

  // *Restricted Function* to add Principals to the acl.HashMap. (When called, the function checks the caller against the "acl.HashMap" for authorization)
  // To make the calls from the deployer canister use the dfx command: $dfx canister call canister_name addPrincipal '( "exampleId", "examplePrincipal" )'
  public shared(msg) func addPrincipal(id: Text, newPrincipal: Text): async Text { // Sintax: https://internetcomputer.org/docs/current/motoko/main/writing-motoko/caller-id#:~:text=public%20shared(msg)%20func%20inc()%20%3A%20async%20()%20%7B Adding Access Control https://internetcomputer.org/docs/current/motoko/main/writing-motoko/caller-id
    let callerPrincipal = Principal.toText(msg.caller); // Get the caller's principal as text // FYI: on update Functions the caller sintax is different: public shared(msg) func myFunction(i: Text, n: Text): async(){ 
    switch (acl.get(callerPrincipal)) { // Check if the caller is in the ACL
      case (?principalSet) { // If the caller is authorized, add the new principal to the ACL
        acl.put(id, newPrincipal);
        return "The Principal ID: " # newPrincipal # " has been successfully added to the Access List";
      };
      case (null) { 
        return "You are not authorized to add principals to the Access List";
      }
    }
  };
}
