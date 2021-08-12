type ulong = Unsigned.ULong.t

module Reachable_ptr : sig
  (** Pointers with a GC link from the structure they are in.
      These are like [Ctypes.ptr] except that [setf] will add a link (through a
      finalizer) from the structure to the pointer to prevent its early
      collection. *)

  type 'a t

  val typ : 'a Ctypes_static.typ -> 'a t Ctypes_static.typ
  (** Ctypes type. *)

  val setf :
       ('b, 'c) Ctypes.structured
    -> ('a t, ('b, 'c) Ctypes.structured) Ctypes.field
    -> 'a Ctypes.ptr
    -> unit
  (** Combine [Ctypes.setf] and [create].
      The parent object is set to the structured value. *)

  val getf :
       ('b, 'c) Ctypes.structured
    -> ('a t, ('b, 'c) Ctypes.structured) Ctypes.field
    -> 'a Ctypes.ptr
  (** Call [Ctypes.getf] and unwrap the result. *)

  val is_null : 'a t -> bool
  (** Call [Ctypes.is_null] on the underlying pointer *)
end

(******************************************************************************)
(*                    String conversions to/from C pointers                   *)
(******************************************************************************)

val ptr_from_string : string -> char Ctypes.ptr
(** [ptr_from_string s] allocates memory for a C string with length
    [String.length s] and content copied from [s]. The string is not
    [null] terminated. *)

val string_from_ptr : char Ctypes.ptr -> length:int -> string
(** [string_from_ptr] allocates an OCaml string. *)

val string_from_carray : char Ctypes.CArray.t -> string
(** [string_from_carray array] allocates a fresh OCaml string
    whose content are copied from [array]. *)

val carray_from_string : string -> char Ctypes.CArray.t
(** [carray_from_string] allocates a fresh array, whose content is
    identical to the string [s]. The resulting C string is not null
    terminated. *)

val string_copy : string -> int -> char Ctypes.ptr -> unit
(** [string_copy str length ptr] copy the content of [str] into the
    [length] bytes of memory pointed to by [ptr]. *)

val make_string :
     string
  -> 'a Ctypes.structure
  -> (Unsigned.ULong.t, 'a Ctypes.structure) Ctypes.field
  -> ('b Reachable_ptr.t, 'a Ctypes.structure) Ctypes.field
  -> unit
(**
 * Copy an OCaml string to a Ctypes struct.
 *
 * Parameters:
 *   - str is the source string
 *   - p is the structure
 *   - lengthField is the field within that struct that holds then length
 *   - dataField   idem for data
 *   - typ is the type of the data
 *)

val view_string :
     'b Ctypes.structure
  -> (ulong, 'b Ctypes.structure) Ctypes.field
  -> ('a Reachable_ptr.t, 'b Ctypes.structure) Ctypes.field
  -> string
(**
 * Read an OCaml string from a Ctypes struct.
 *
 * Parameters: same as make_string.
 *)

val make_string_option :
     string option
  -> ('a, [`Struct]) Ctypes.structured
  -> (Unsigned.ULong.t, ('a, [`Struct]) Ctypes.structured) Ctypes.field
  -> ('b Reachable_ptr.t, ('a, [`Struct]) Ctypes.structured) Ctypes.field
  -> unit
(**
 * Copy a string option to a pointer + length.
 * Copying None sets the pointer to NULL and length to 0.
 * Parameters are the same as make_string.
 *)

val view_string_option :
     ('a, [`Struct]) Ctypes.structured
  -> (ulong, 'a Ctypes.structure) Ctypes.field
  -> ('b Reachable_ptr.t, ('a, [`Struct]) Ctypes.structured) Ctypes.field
  -> string option
(**
 * Make a string option out of a pointer + length.
 * Same semantics for copy as make_string_option.
 * Same arguments as view_string.
 *)

exception Buffer_overflow

val blank_padded : length:int -> string -> string
(** Pad a string with ' ' up to [length]. Raises [Buffer_overflow] if
    the string is too long.  *)

val packed_field :
     't Ctypes.typ
  -> string
  -> 'a Ctypes.typ
  -> ( 'a
     , (('s, [< `Struct | `Union]) Ctypes_static.structured as 't) )
     Ctypes.field
(** Like [Ctypes.field] except that it will always align to 1 byte. *)

val smart_field :
     't Ctypes.typ
  -> string
  -> 'a Ctypes.typ
  -> ( 'a
     , (('s, [< `Struct | `Union]) Ctypes_static.structured as 't) )
     Ctypes.field
(** On unix, act like [Ctypes.field]. On windows, act like [packed_field]. *)

val with_out_fmt : string -> (Format.formatter -> 'a) -> 'a
(** Open a file for writing and returns a formatter to it. *)
