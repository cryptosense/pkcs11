(** Object handles ([CK_OBJECT_HANDLE]) *)
type t = P11_ulong.t [@@deriving eq, ord, show, yojson]

val typ : t Ctypes.typ
