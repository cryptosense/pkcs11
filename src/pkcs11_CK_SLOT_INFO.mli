(** Information about a slot ([CK_SLOT_INFO]) *)
type _t
type t = _t Ctypes.structure

type u =
  {
    slotDescription: string;
    manufacturerID : string;
    flags: Pkcs11_CK_FLAGS.t;
    hardwareVersion: P11_version.t;
    firmwareVersion: P11_version.t;
  }

val make : u -> t
val view : t -> u
val string_of_flags : Pkcs11_CK_FLAGS.t -> string
val to_string : ?newlines: bool -> ?indent: string -> u -> string
val to_strings: u -> string list

val ck_slot_info : t Ctypes.typ
