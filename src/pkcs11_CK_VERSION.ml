open Ctypes

(** _t is a type variable that is used to constraint the [Ctypes]
representation. It would appear in the signature of [Version] for
instance. However, to make it more palatable for the outside world,
what is exported is [t], which is defined as [_t structure]. For
some modules, it is quite easy to work with [t] seen as an abstract
time. For other modules, we provide a [u]ser version of the type,
with suitable functions. *)

type _t

type t = _t structure

let ck_version : t typ = structure "CK_VERSION"


let (-:) ty label = Ctypes_helpers.smart_field ck_version label ty
let major = Pkcs11_CK_BYTE.typ -: "major"
let minor = Pkcs11_CK_BYTE.typ -: "minor"
let () = seal ck_version

type u =
  {
    major: int;             (* ck_byte *)
    minor: int;             (* ck_byte *)
  }

let view (c:t) : u =
  {
    major = Pkcs11_CK_BYTE.to_int (getf c major);
    minor = Pkcs11_CK_BYTE.to_int (getf c minor);
  }

let make (u:u) : t =
  let t = Ctypes.make ck_version in
  setf t major (Pkcs11_CK_BYTE.of_int u.major);
  setf t minor (Pkcs11_CK_BYTE.of_int u.minor);
  t

let to_string u =
  Printf.sprintf "%i.%i" u.major u.minor
