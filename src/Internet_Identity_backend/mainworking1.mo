//Version 1.0 Working Code!
//This is the first commit of a working Principal authentication code
//However this only authenticates the Anonymous Principal ID.
//Meaning if you log in with another intener Identity, they wont be able to call the Authgreet Function. (Only anoynoums principal can!)

import Principal "mo:base/Principal";
import Text "mo:base/Text";

actor {
  public query msg func whoAmI() : async Principal {
    return msg.caller;
  };

  public query func greet(name : Text) : async Text {
    return "Hello, " # name # "!";
  };

  public query msg func Authgreet(name : Text): async Text  {
    let anon = Principal.fromText("2vxsx-fae"); // "Principal.fromText" Converts a Text representation of a Principal to a Principal value.
      if (msg.caller == anon) { // If the caller "msg" is equal to the variable "anon" // TRUE than do the following:
        return "Hello, " # name # "!";
      } else {
        return "not authorized"
      }
  };
}



