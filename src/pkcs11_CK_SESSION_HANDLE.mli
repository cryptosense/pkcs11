(** Session handles ([CK_SESSION_HANDLE]) *)
type t = Pkcs11_CK_ULONG.t
[@@deriving yojson]
val typ : t Ctypes.typ
