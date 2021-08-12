(** Session handles ([CK_SESSION_HANDLE]) *)
type t = P11_ulong.t [@@deriving yojson]

val typ : t Ctypes.typ
