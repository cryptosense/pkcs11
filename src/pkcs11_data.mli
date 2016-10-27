(** Data: input and output of encryption functions. *)

(** An element of type [t] is a structure made of a pointer to a C
    string, and its length. It is easy to convert this type to and
    from OCaml strings.

    The reason we use this type is that some PKCS#11 functions
    require a two step interraction, in which one first gives a null
    pointer (with length 0) to a function, which modifies the length
    of the data. Then, the user allocates memory for this Data.t, and
    performs a second call to the function.*)

type t

val to_string : t -> string
val of_string : string -> t

val string_of_raw : 'a Ctypes.ptr -> Unsigned.ULong.t -> string

(** [create ()] allocates a new [t] with length 0, and content the
    null pointer.*)
val create : unit -> t

(** [allocate t] updates the content of the [t] structure to point
    to freshly allocated memory. *)
val allocate: t -> unit

val get_content : t -> Pkcs11_CK_BYTE.t Ctypes.ptr
val get_length : t -> Pkcs11_CK_ULONG.t
val get_length_addr : t -> Pkcs11_CK_ULONG.t Ctypes.ptr
