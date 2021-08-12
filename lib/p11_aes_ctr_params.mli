(**
   Counters for AES CTR.
   In PKCS11 applications:
   - [bits] must be between 1 and 128, inclusive.
   It represents the number of bits that will act as a counter in [block].
   - [block] must be a 16-byte string.
   Its counter part (big endian) is at the end.

   These invariants are not checked, in order to represent invalid states that
   DLLs may return.
*)

type t [@@deriving eq, ord, show, yojson]

val make : bits:P11_ulong.t -> block:string -> t

val bits : t -> P11_ulong.t

val block : t -> string
