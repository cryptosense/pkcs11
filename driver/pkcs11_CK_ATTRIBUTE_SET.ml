open Ctypes
open Pkcs11_CK_ATTRIBUTE

let _setter_ :
    (unit Ctypes.ptr -> 'a -> unit) -> Unsigned.ULong.t -> t -> 'a -> P11_rv.t =
 fun ff size t elem ->
  if pvalue_is_null_ptr t then (
    setf t ulValueLen size;
    P11_rv.CKR_OK
  ) else if getf t ulValueLen >= size then (
    ff (Ctypes_helpers.Reachable_ptr.getf t pValue) elem;
    setf t ulValueLen size;
    P11_rv.CKR_OK
  ) else (
    setf t ulValueLen Unsigned.ULong.max_int;
    P11_rv.CKR_BUFFER_TOO_SMALL
  )

let _setter typ converter =
  _setter_ (fun ptr elem -> Ctypes.from_voidp typ ptr <-@ converter elem)

let boolean =
  _setter Pkcs11_CK_BBOOL.typ
    (function
      | true -> Pkcs11_CK_BBOOL._CK_TRUE
      | false -> Pkcs11_CK_BBOOL._CK_FALSE)
    (Unsigned.ULong.of_int (sizeof uint8_t))

let ulong =
  _setter Ctypes.ulong
    (fun x -> x)
    (Unsigned.ULong.of_int (sizeof Ctypes.ulong))

let key_gen_mechanism =
  _setter Ctypes.ulong Pkcs11_key_gen_mechanism.make
    (Unsigned.ULong.of_int (sizeof Ctypes.ulong))

let string t elem =
  _setter_
    (fun p s ->
      let ptr = Ctypes.from_voidp Ctypes.char p in
      String.iteri (fun i c -> ptr +@ i <-@ c) s)
    (Unsigned.ULong.of_int (String.length elem))
    t elem

let bigint t elem = string t (P11_bigint.encode elem)

let set_access_error t = setf t ulValueLen Unsigned.ULong.max_int

let update (P11_attribute.Pack x) t =
  let open P11_attribute_type in
  match x with
  | (CKA_CLASS, cko) -> ulong t (Pkcs11_CK_OBJECT_CLASS.make cko)
  | (CKA_TOKEN, b) -> boolean t b
  | (CKA_PRIVATE, b) -> boolean t b
  | (CKA_LABEL, s) -> string t s
  | (CKA_VALUE, s) -> string t s
  | (CKA_TRUSTED, b) -> boolean t b
  | (CKA_CHECK_VALUE, _) -> assert false
  | (CKA_KEY_TYPE, ckk) -> ulong t (Pkcs11_CK_KEY_TYPE.make ckk)
  | (CKA_SUBJECT, s) -> string t s
  | (CKA_ID, s) -> string t s
  | (CKA_SENSITIVE, b) -> boolean t b
  | (CKA_ENCRYPT, b) -> boolean t b
  | (CKA_DECRYPT, b) -> boolean t b
  | (CKA_WRAP, b) -> boolean t b
  | (CKA_UNWRAP, b) -> boolean t b
  | (CKA_SIGN, b) -> boolean t b
  | (CKA_SIGN_RECOVER, b) -> boolean t b
  | (CKA_VERIFY, b) -> boolean t b
  | (CKA_VERIFY_RECOVER, b) -> boolean t b
  | (CKA_DERIVE, b) -> boolean t b
  | (CKA_START_DATE, _) -> assert false
  | (CKA_END_DATE, _) -> assert false
  | (CKA_MODULUS, n) -> bigint t n
  | (CKA_MODULUS_BITS, ul) -> ulong t ul
  | (CKA_PUBLIC_EXPONENT, n) -> bigint t n
  | (CKA_PRIVATE_EXPONENT, n) -> bigint t n
  | (CKA_PRIME_1, n) -> bigint t n
  | (CKA_PRIME_2, n) -> bigint t n
  | (CKA_EXPONENT_1, n) -> bigint t n
  | (CKA_EXPONENT_2, n) -> bigint t n
  | (CKA_COEFFICIENT, n) -> bigint t n
  | (CKA_PRIME, n) -> bigint t n
  | (CKA_SUBPRIME, n) -> bigint t n
  | (CKA_BASE, n) -> bigint t n
  | (CKA_PRIME_BITS, _) -> assert false
  | (CKA_SUBPRIME_BITS, _) -> assert false
  | (CKA_VALUE_LEN, ul) -> ulong t ul
  | (CKA_EXTRACTABLE, b) -> boolean t b
  | (CKA_LOCAL, b) -> boolean t b
  | (CKA_NEVER_EXTRACTABLE, b) -> boolean t b
  | (CKA_ALWAYS_SENSITIVE, b) -> boolean t b
  | (CKA_KEY_GEN_MECHANISM, m) -> key_gen_mechanism t m
  | (CKA_MODIFIABLE, b) -> boolean t b
  | (CKA_EC_PARAMS, _) -> assert false
  | (CKA_EC_POINT, _) -> assert false
  | (CKA_ALWAYS_AUTHENTICATE, b) -> boolean t b
  | (CKA_WRAP_WITH_TRUSTED, b) -> boolean t b
  | (CKA_WRAP_TEMPLATE, _) -> assert false
  | (CKA_UNWRAP_TEMPLATE, _) -> assert false
  | (CKA_ALLOWED_MECHANISMS, _) -> assert false
  | (CKA_CS_UNKNOWN _, _) -> assert false
