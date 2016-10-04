(** Information about a session ([CK_SESSION_INFO]) *)
type _t
type t = _t Ctypes.structure

type u =
  {
    slotID: Unsigned.ULong.t;
    state: Unsigned.ULong.t;
    flags: Pkcs11_CK_FLAGS.t;
    ulDeviceError: Unsigned.ULong.t;
  }

val make : u -> t
val view : t -> u
val string_of_flags : Pkcs11_CK_FLAGS.t -> string
val to_string : ?newlines: bool -> ?indent: string -> u -> string
val to_strings : u -> string list

val ck_session_info : t Ctypes.typ
