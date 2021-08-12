(** Information about a session ([CK_SESSION_INFO]) *)
type _t

type t = _t Ctypes.structure

val make : P11_session_info.t -> t

val view : t -> P11_session_info.t

val ck_session_info : t Ctypes.typ
