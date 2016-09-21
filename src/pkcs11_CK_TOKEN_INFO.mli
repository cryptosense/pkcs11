(** Token information. *)
type _t
type t = _t Ctypes.structure

type u =
  {
    label: string;
    manufacturerID:string;
    model: string;
    serialNumber: string;
    flags: Pkcs11_CK_FLAGS.t;
    ulMaxSessionCount: Unsigned.ULong.t;
    ulSessionCount: Unsigned.ULong.t;
    ulMaxRwSessionCount: Unsigned.ULong.t;
    ulRwSessionCount: Unsigned.ULong.t;
    ulMaxPinLen: Unsigned.ULong.t;
    ulMinPinLen          : Unsigned.ULong.t;
    ulTotalPublicMemory  : Unsigned.ULong.t;
    ulFreePublicMemory   : Unsigned.ULong.t;
    ulTotalPrivateMemory : Unsigned.ULong.t;
    ulFreePrivateMemory  : Unsigned.ULong.t;
    hardwareVersion : Pkcs11_CK_VERSION.u;
    firmwareVersion : Pkcs11_CK_VERSION.u;
    utcTime: string
  }

val make : u -> t
val view : t -> u
val string_of_flags : Pkcs11_CK_FLAGS.t -> string
val to_string : ?newlines: bool -> ?indent: string -> u -> string
val to_strings : u -> string list

(* returns correct string value if the unsigned long has a special value
 * e.g. CK_UNAVAILABLE_INFORMATION *)
val ul_to_string : Unsigned.ULong.t -> string

val ck_token_info : t Ctypes.typ
