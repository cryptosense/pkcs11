open Ctypes

(******************************************************************************)
(*                         Dealing with null pointers                         *)
(******************************************************************************)

exception Null_pointer

let safe_deref p =
  if Ctypes.ptr_compare (to_voidp p) null = 0
  then raise Null_pointer
  else Ctypes.(!@) p

(* There is currently no [is_null] function in Ctypes.  Apparently
   [(=)] is NOT the way to go and cause segfault. *)
let is_null (type a)(x : a Ctypes.ptr) : bool =
  Ctypes.(ptr_compare null (to_voidp x)) = 0

module Reachable_ptr : sig
  type 'a t
  val typ : 'a Ctypes_static.typ -> 'a t Ctypes_static.typ
  val setf : ('b, 'c) Ctypes.structured ->
    ('a t, ('b, 'c) Ctypes.structured) Ctypes.field -> 'a Ctypes.ptr -> unit
  val getf : ('b, 'c) Ctypes.structured ->
    ('a t, ('b, 'c) Ctypes.structured) Ctypes.field -> 'a Ctypes.ptr
end = struct

  type 'a t = 'a ptr

  let typ = Ctypes.ptr

  (** Add a GC dependency from one object to another:
      while [from] is reachable, [to_] is reachable too. *)
  let add_gc_link ~from ~to_ =
    let r = ref (Some (Obj.repr to_)) in
    let finaliser _ = r := None in
    Gc.finalise finaliser from

  let setf s f v =
    add_gc_link ~from:s ~to_:v;
    Ctypes.setf s f v

  let getf = Ctypes.getf

end

(******************************************************************************)
(*                                    Ulong                                   *)
(******************************************************************************)
type ulong = Unsigned.ULong.t

(******************************************************************************)
(*                         Conversion to/from strings                         *)
(******************************************************************************)


(** [ptr_from_string s] allocates memory for a C string with length
    [String.length s] and content copied from [s]. The string is not
    [null] terminated. *)
let ptr_from_string (s: string) : char ptr =
  let n = String.length s in
  let data = allocate_n char ~count:n in
  String.iteri (fun i c -> (data +@ i) <-@ c) s;
  data

(** [string_from_ptr] allocates an OCaml string. *)
let string_from_ptr = Ctypes.string_from_ptr

(** [string_from_carray array] allocates a fresh OCaml string
    whose content are copied from [array]. *)
let string_from_carray (array: char CArray.t) : string =
  string_from_ptr ~length:(CArray.length array) (CArray.start array)

(** [carray_from_string] allocates a fresh array, whose content is
    identical to the string [s]. The resulting C string is not null
    terminated. *)
let carray_from_string (s: string) : char CArray.t =
  let p = ptr_from_string s in CArray.from_ptr p (String.length s)

(** [string_copy str length ptr] copy the content of [str] into the
    [length] bytes of memory pointed to by [ptr]. *)
let string_copy (str:string) length (ptr: char ptr) : unit =
  assert (String.length str = length);
  String.iteri (fun i c -> (ptr +@ i) <-@ c) str;
  ()


(******************************************************************************)
(*                                     Struct                                 *)
(******************************************************************************)

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
let make_string
    (type s)
    (type data)
    (str: string)
    (p: s structure)
    (lengthField: (Unsigned.ULong.t,s structure) field)
    (dataField: (data Reachable_ptr.t, s structure) field)
  : unit =
  let len = String.length str in
  let ptr = allocate_n char ~count:len in
  String.iteri (fun i c -> (ptr +@ i) <-@ c) str;
  setf p lengthField (Unsigned.ULong.of_int len);
  let ptr_typed = coerce Ctypes.(ptr char) Ctypes.(field_type dataField) ptr in
  setf p dataField ptr_typed

(**
 * Read an OCaml string from a Ctypes struct.
 *
 * Parameters: same as make_string.
 *)
let view_string
    (type s)
    (p: s structure)
    (lengthField: (ulong, s structure) field)
    (dataField: ('a Reachable_ptr.t, s structure) field) : string =
  let length = Unsigned.ULong.to_int @@ getf p lengthField in
  let ptr = from_voidp char @@ to_voidp @@ Reachable_ptr.getf p dataField in
  string_from_ptr ptr ~length

(**
 * Copy a string option to a pointer + length.
 * Copying None sets the pointer to NULL and length to 0.
 * Parameters are the same as make_string.
 *)
let make_string_option stro p lengthField dataField =
  match stro with
    | None -> begin
        let typ = Ctypes.field_type dataField in
      setf p dataField (Ctypes.coerce (ptr void) typ null);
      setf p lengthField (Unsigned.ULong.zero)
    end
  | Some str -> make_string str p lengthField dataField


(**
 * Make a string option out of a pointer + length.
 * Same semantics for copy as make_string_option.
 * Same arguments as view_string.
 *)
let view_string_option p lengthField dataField =
  if is_null (Reachable_ptr.getf p dataField) then
    None
  else
    Some (view_string p lengthField dataField)

(******************************************************************************)
(*                             String operations                              *)
(******************************************************************************)

exception Buffer_overflow
let blank_padded ~length s =
  let s_length = String.length s in
  if s_length = length
  then s
  else if String.length s < length
  then s ^ (String.make (length - s_length) ' ')
  else raise Buffer_overflow

(* Remove trailing zeros and spaces, and quote the result to prevent
   the DLL from injecting stuff into our tool. *)
let trim_and_quote string =
  let len = String.length string in
  let rec new_len i =
    if i < 0 then
      0
    else match string.[i] with
      | '\000' | ' ' ->
          new_len (i - 1)
      | _ ->
          i + 1
  in
  let new_len = new_len (len - 1) in
  Printf.sprintf "%S" (Str.first_chars string new_len)

(* Adjusted from ctypes source. *)
let packed_field (type k) (structured : (_, k) structured typ) label ftype =
  let open Ctypes_static in
  match structured with
    | Struct ({ spec = Incomplete spec } as s) ->
        let foffset = spec.isize in
        let field = { ftype; foffset; fname = label } in
        begin
          spec.isize <- foffset + sizeof ftype;
          s.fields <- BoxedField field :: s.fields;
          field
        end
    | Union ({ uspec = None } as u) ->
        let field = { ftype; foffset = 0; fname = label } in
        u.ufields <- BoxedField field :: u.ufields;
        field
    | Struct { tag; spec = Complete _ } -> raise (Ctypes_static.ModifyingSealedType tag)
    | Union { utag } -> raise (Ctypes_static.ModifyingSealedType utag)
    | Abstract _ -> raise (Ctypes_static.Unsupported "Adding a field to non-structured type")
    | Primitive _
    | View _
    | Bigarray _ -> raise (Ctypes_static.Unsupported "Adding a field to non-structured type")

let smart_field =
  if Sys.unix then
    Ctypes.field
  else
    packed_field

let with_out_fmt filename f =
  let oc = open_out filename in
  let fmt = Format.formatter_of_out_channel oc in
  let finally () = close_out oc in
  let result =
    try f fmt with
      | Sys.Break as exn
      | exn -> begin
          close_out_noerr oc;
          raise exn
        end
  in
  finally ();
  result
