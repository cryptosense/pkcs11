(**
   Big integers used in PKCS#11.

   PKCS#11 expects them to be encoded in big-endian,
   so manipulating the underlying representation is error-prone.

   The name is not explicitly stated in the standard but is used to avoid
   collisions with [Big_int].
*)

type t
[@@deriving yojson]

(** Convert to/from a big-endian byte array. *)
val encode : t -> string
val decode : string -> t

val to_int : t -> int
val of_int : int -> t

val equal : t -> t -> bool
val compare : t -> t -> int

val to_string : t -> string

val zero : t

val of_z : Z.t -> t
val to_z : t -> Z.t
