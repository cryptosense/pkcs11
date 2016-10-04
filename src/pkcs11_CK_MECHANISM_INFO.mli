(** Information about a particular mechanism ([CK_MECHANISM_INFO]) *)

type _t
type t = _t Ctypes.structure

type u =
    {
      ulMinKeySize: Unsigned.ULong.t;
      ulMaxKeySize: Unsigned.ULong.t;
      flags: Pkcs11_CK_FLAGS.t;
    }
val make : u -> t
val view : t -> u
val string_of_flags : Pkcs11_CK_FLAGS.t -> string
val strings_of_flags : Pkcs11_CK_FLAGS.t -> string list
val allowed_flags : Pkcs11_CK_FLAGS.t
val to_string : ?newlines: bool -> ?indent: string -> u -> string
val to_strings : u -> string list

val ck_mechanism_info : t Ctypes.typ
