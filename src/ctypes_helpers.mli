type ulong = Unsigned.ULong.t

module Reachable_ptr : sig
  (** Pointers with a GC link from the structure they are in.
      These are like [Ctypes.ptr] except that [setf] will add a link (through a
      finalizer) from the structure to the pointer to prevent its early
      collection. *)

  type 'a t

  (** Ctypes type. *)
  val typ : 'a Ctypes_static.typ -> 'a t Ctypes_static.typ

  (** Combine [Ctypes.setf] and [create].
      The parent object is set to the structured value. *)
  val setf : ('b, 'c) Ctypes.structured ->
    ('a t, ('b, 'c) Ctypes.structured) Ctypes.field -> 'a Ctypes.ptr -> unit

  (** Call [Ctypes.getf] and unwrap the result. *)
  val getf : ('b, 'c) Ctypes.structured ->
    ('a t, ('b, 'c) Ctypes.structured) Ctypes.field -> 'a Ctypes.ptr
end

(******************************************************************************)
(*                    String conversions to/from C pointers                   *)
(******************************************************************************)

(** [ptr_from_string s] allocates memory for a C string with length
    [String.length s] and content copied from [s]. The string is not
    [null] terminated. *)
val ptr_from_string : string -> char Ctypes.ptr

(** [string_from_ptr] allocates an OCaml string. *)
val string_from_ptr : char Ctypes.ptr -> length:int -> string

(** [string_from_carray array] allocates a fresh OCaml string
    whose content are copied from [array]. *)
val string_from_carray : char Ctypes.CArray.t -> string

(** [carray_from_string] allocates a fresh array, whose content is
    identical to the string [s]. The resulting C string is not null
    terminated. *)
val carray_from_string : string -> char Ctypes.CArray.t

(** [string_copy str length ptr] copy the content of [str] into the
    [length] bytes of memory pointed to by [ptr]. *)
val string_copy : string -> int -> char Ctypes.ptr -> unit


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
val make_string :
  string ->
  'a Ctypes.structure ->
  (Unsigned.ULong.t, 'a Ctypes.structure) Ctypes.field ->
  ('b Reachable_ptr.t, 'a Ctypes.structure) Ctypes.field -> unit

(**
 * Read an OCaml string from a Ctypes struct.
 *
 * Parameters: same as make_string.
 *)
val view_string :
  'b Ctypes.structure ->
  (ulong, 'b Ctypes.structure) Ctypes.field ->
  ('a Reachable_ptr.t, 'b Ctypes.structure) Ctypes.field -> string

(**
 * Copy a string option to a pointer + length.
 * Copying None sets the pointer to NULL and length to 0.
 * Parameters are the same as make_string.
 *)
val make_string_option :
  string option ->
  ('a, [ `Struct ]) Ctypes.structured ->
  (Unsigned.ULong.t, ('a, [ `Struct ]) Ctypes.structured) Ctypes.field ->
  ('b Reachable_ptr.t, ('a, [ `Struct ]) Ctypes.structured) Ctypes.field -> unit

(**
 * Make a string option out of a pointer + length.
 * Same semantics for copy as make_string_option.
 * Same arguments as view_string.
 *)
val view_string_option :
  ('a, [ `Struct ]) Ctypes.structured ->
  (ulong, 'a Ctypes.structure) Ctypes.field ->
  ('b Reachable_ptr.t, ('a, [ `Struct ]) Ctypes.structured) Ctypes.field ->
  string option

exception Buffer_overflow

(** Pad a string with ' ' up to [length]. Raises [Buffer_overflow] if
    the string is too long.  *)
val blank_padded : length:int -> string -> string

(** Remove trailing zeros and spaces, and quote the result.*)
val trim_and_quote : string -> string

(** Like [Ctypes.field] except that it will always align to 1 byte. *)
val packed_field : 't Ctypes.typ -> string -> 'a Ctypes.typ -> ('a, (('s, [<`Struct | `Union]) Ctypes_static.structured as 't)) Ctypes.field

(** On unix, act like [Ctypes.field]. On windows, act like [packed_field]. *)
val smart_field : 't Ctypes.typ -> string -> 'a Ctypes.typ -> ('a, (('s, [<`Struct | `Union]) Ctypes_static.structured as 't)) Ctypes.field

(** Open a file for writing and returns a formatter to it. *)
val with_out_fmt : string -> (Format.formatter -> 'a) -> 'a
