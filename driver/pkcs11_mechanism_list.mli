(** An element of type [t] is a structure made of a pointer to a C
    array, and its length.

    The reason we use this type is that some PKCS#11 functions
    require a two step interraction, in which one first gives a null
    pointer (with length 0) to a function, which modifies the length
    of the list. Then, the user allocates memory for this list, and
    performs a second call to the function.*)

type t

val create : unit -> t
(** [create ()] allocates a new [t] with length 0, and content the
    null pointer.*)

val allocate : t -> unit
(** [allocate t] updates the content of the [t] structure to point
    to freshly allocated memory. *)

val of_raw :
  Pkcs11_CK_MECHANISM_TYPE.t Ctypes.ptr -> P11_ulong.t Ctypes.ptr -> t

type u = P11_mechanism_type.t list

val make : u -> t

val view : t -> u

val get_content : t -> Pkcs11_CK_MECHANISM_TYPE.t Ctypes.ptr

val get_length_addr : t -> P11_ulong.t Ctypes.ptr
