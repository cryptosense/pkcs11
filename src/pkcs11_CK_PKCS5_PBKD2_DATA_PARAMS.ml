open Ctypes
open Ctypes_helpers

type _t
type t = _t structure
let t: t typ = structure "CK_PKCS5_PBKD2_DATA_PARAMS"

let (-:) typ label = smart_field t label typ
let saltSource = Pkcs11_CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE.typ -: "saltSource"
let pSaltSourceData = ptr void -: "pSaltSourceData"
let ulSaltSourceDataLen = ulong -: "ulSaltSourceDataLen"
let iterations = ulong -: "iterations"
let prf = Pkcs11_CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE.typ -: "prf"
let pPrfData = ptr void -: "pPrfData"
let ulPrfDataLen = ulong -: "ulPrfDataLen"
let pPassword = ptr char -: "pPassword"
let pPasswordLen = ptr ulong -: "pPasswordLen"
let () = seal t

type u =
  {
    saltSource: Pkcs11_CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE.u;
    saltSourceData: string option;
    iterations: int;
    prf: Pkcs11_CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE.u;
    prfData: string option;
    password: string;
  }

let compare =
  Pervasives.compare

let make (u: u): t =
  let t = Ctypes.make t in
  setf t saltSource @@ Pkcs11_CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE.make u.saltSource;
  make_string_option u.saltSourceData t ulSaltSourceDataLen pSaltSourceData;
  setf t iterations (Unsigned.ULong.of_int u.iterations);
  setf t prf @@ Pkcs11_CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE.make u.prf;
  make_string_option u.prfData t ulPrfDataLen pPrfData;
  setf t pPassword @@ ptr_from_string u.password;
  setf t pPasswordLen @@ Ctypes.allocate ulong (
    Unsigned.ULong.of_int @@ String.length u.password
  );
  t

let view (t: t): u =
  let saltSource = Pkcs11_CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE.view @@ getf t saltSource in
  let saltSourceData = view_string_option t ulSaltSourceDataLen pSaltSourceData in
  let iterations = Unsigned.ULong.to_int @@ getf t iterations in
  let prf = Pkcs11_CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE.view @@ getf t prf in
  let prfData = view_string_option t ulPrfDataLen pPrfData in
  let password =
    let pPassword = getf t pPassword in
    let pPasswordLen = getf t pPasswordLen in
    let pPasswordLen = !@ pPasswordLen in
    string_from_ptr
      ~length: (Unsigned.ULong.to_int pPasswordLen)
      pPassword
  in
  {
    saltSource;
    saltSourceData;
    iterations;
    prf;
    prfData;
    password;
  }
