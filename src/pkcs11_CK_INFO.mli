(** Driver information ([CK_INFO]) *)
type _t
type t = _t Ctypes.structure

type u =
  {
    cryptokiVersion : P11_version.t;
    manufacturerID : string;
    flags : Pkcs11_CK_FLAGS.t;
    libraryDescription : string;
    libraryVersion : P11_version.t;
  }
val make : u -> t
val view : t -> u
val string_of_flags : Pkcs11_CK_FLAGS.t -> string
val to_string : ?newlines: bool -> ?indent: string -> u -> string
val to_strings : u -> string list

val ck_info : t Ctypes.typ
