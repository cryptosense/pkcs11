(** Unsigned values (at least 32 bits long) ([CK_ULONG]) *)
type t = Unsigned.ulong [@@deriving eq, ord, show, yojson]

val _CK_EFFECTIVELY_INFINITE : t
(** EFFECTIVELY_INFINITE constant specified in PKCS11 *)

val _CK_UNAVAILABLE_INFORMATION : t
(** UNAVAILABLE INFORMATION constant specified in PKCS11 *)

val is_effectively_infinite : t -> bool

val is_unavailable_information : t -> bool
