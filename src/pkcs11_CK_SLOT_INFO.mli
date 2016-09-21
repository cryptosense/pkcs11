type _t
type t = _t Ctypes.structure

type u =
  {
    slotDescription: string;
    manufacturerID : string;
    flags: Pkcs11_CK_FLAGS.t;
    hardwareVersion: Pkcs11_CK_VERSION.u;
    firmwareVersion: Pkcs11_CK_VERSION.u;
  }

val make : u -> t
val view : t -> u
val string_of_flags : Pkcs11_CK_FLAGS.t -> string
val to_string : ?newlines: bool -> ?indent: string -> u -> string
val to_strings: u -> string list

val ck_slot_info : t Ctypes.typ
