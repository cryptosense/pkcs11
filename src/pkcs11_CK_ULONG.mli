(** Unsigned values (at least 32 bits long) ([CK_ULONG]) *)
type t = Unsigned.ulong
val compare : t -> t -> int

(** EFFECTIVELY_INFINITE constant specified in PKCS11 *)
val _CK_EFFECTIVELY_INFINITE : t

(** UNAVAILABLE INFORMATION constant specified in PKCS11 *)
val _CK_UNAVAILABLE_INFORMATION : t

val is_effectively_infinite : t -> bool
val is_unavailable_information : t -> bool
