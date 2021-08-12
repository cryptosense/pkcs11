type t = Unsigned.ULong.t [@@deriving ord]

let equal = Stdlib.( = )

let show = Unsigned.ULong.to_string

let pp fmt n = Format.pp_print_string fmt (show n)

let ( ! ) x = Unsigned.ULong.of_string (Int64.to_string x)

let empty = Unsigned.ULong.zero

let logical_or = Unsigned.ULong.logor

let ( || ) = logical_or

let logical_and = Unsigned.ULong.logand

let get ~(flags : t) ~(flag : t) : bool =
  not (equal (logical_and flags flag) empty)

type domain =
  | Info_domain
  | Slot_info_domain
  | Token_info_domain
  | Session_info_domain
  | Mechanism_info_domain
  | Initialize_domain
  | Wait_for_slot_domain
  | OTP_signature_info_domain
  | Any_domain

(* CK_SLOT_INFO *)
let _CKF_TOKEN_PRESENT = !0x00000001L

let _CKF_REMOVABLE_DEVICE = !0x00000002L

let _CKF_HW_SLOT = !0x00000004L

(* CK_TOKEN_INFO *)
let _CKF_RNG = !0x00000001L

let _CKF_WRITE_PROTECTED = !0x00000002L

let _CKF_LOGIN_REQUIRED = !0x00000004L

let _CKF_USER_PIN_INITIALIZED = !0x00000008L

let _CKF_RESTORE_KEY_NOT_NEEDED = !0x00000020L

let _CKF_CLOCK_ON_TOKEN = !0x00000040L

let _CKF_PROTECTED_AUTHENTICATION_PATH = !0x00000100L

let _CKF_DUAL_CRYPTO_OPERATIONS = !0x00000200L

let _CKF_TOKEN_INITIALIZED = !0x00000400L

let _CKF_SECONDARY_AUTHENTICATION = !0x00000800L

let _CKF_USER_PIN_COUNT_LOW = !0x00010000L

let _CKF_USER_PIN_FINAL_TRY = !0x00020000L

let _CKF_USER_PIN_LOCKED = !0x00040000L

let _CKF_USER_PIN_TO_BE_CHANGED = !0x00080000L

let _CKF_SO_PIN_COUNT_LOW = !0x00100000L

let _CKF_SO_PIN_FINAL_TRY = !0x00200000L

let _CKF_SO_PIN_LOCKED = !0x00400000L

let _CKF_SO_PIN_TO_BE_CHANGED = !0x00800000L

(* CK_SESSION_INFO *)
let _CKF_RW_SESSION = !0x00000002L

let _CKF_SERIAL_SESSION = !0x00000004L

(* The following flag is actually a bit which is present in CKA values
   which consists in an array of attributes. *)
let _CKF_ARRAY_ATTRIBUTE = !0x40000000L

(* CK_MECHANISM_INFO *)
let _CKF_HW = !0x00000001L

let _CKF_ENCRYPT = !0x00000100L

let _CKF_DECRYPT = !0x00000200L

let _CKF_DIGEST = !0x00000400L

let _CKF_SIGN = !0x00000800L

let _CKF_SIGN_RECOVER = !0x00001000L

let _CKF_VERIFY = !0x00002000L

let _CKF_VERIFY_RECOVER = !0x00004000L

let _CKF_GENERATE = !0x00008000L

let _CKF_GENERATE_KEY_PAIR = !0x00010000L

let _CKF_WRAP = !0x00020000L

let _CKF_UNWRAP = !0x00040000L

let _CKF_DERIVE = !0x00080000L

let _CKF_EC_F_P = !0x00100000L

let _CKF_EC_F_2M = !0x00200000L

let _CKF_EC_ECPARAMETERS = !0x00400000L

let _CKF_EC_NAMEDCURVE = !0x00800000L

let _CKF_EC_UNCOMPRESS = !0x01000000L

let _CKF_EC_COMPRESS = !0x02000000L

let _CKF_EXTENSION = !0x80000000L

(* C_Initialize *)
let _CKF_LIBRARY_CANT_CREATE_OS_THREADS = !0x00000001L

let _CKF_OS_LOCKING_OK = !0x00000002L

(* C_WaitForSlotEvent *)
let _CKF_DONT_BLOCK = !0x00000001L

(* CK_OTP_SIGNATURE_INFO *)
let _CKF_NEXT_OTP = !0x00000001L

let _CKF_EXCLUDE_TIME = !0x00000002L

let _CKF_EXCLUDE_COUNTER = !0x00000004L

let _CKF_EXCLUDE_CHALLENGE = !0x00000008L

let _CKF_EXCLUDE_PIN = !0x00000010L

let _CKF_USER_FRIENDLY_OTP = !0x00000020L

let to_string = Unsigned.ULong.to_string

let of_string = Unsigned.ULong.of_string

let to_json ?pretty (flags : t) =
  match pretty with
  | None -> `String (to_string flags)
  | Some pretty ->
    `Assoc
      [("value", `String (to_string flags)); ("string", `String (pretty flags))]

(* for now, just use assoc lists for the mappings as there are not many *)
let pretty_string_mappings =
  (* There are no flags for CK_INFO in v2.20 *)
  let info = [] in

  let slot_info =
    [ (_CKF_TOKEN_PRESENT, "CKF_TOKEN_PRESENT")
    ; (_CKF_REMOVABLE_DEVICE, "CKF_REMOVABLE_DEVICE")
    ; (_CKF_HW_SLOT, "CKF_HW_SLOT") ]
  in

  let token_info =
    [ (_CKF_RNG, "CKF_RNG")
    ; (_CKF_WRITE_PROTECTED, "CKF_WRITE_PROTECTED")
    ; (_CKF_LOGIN_REQUIRED, "CKF_LOGIN_REQUIRED")
    ; (_CKF_USER_PIN_INITIALIZED, "CKF_USER_PIN_INITIALIZED")
    ; (_CKF_RESTORE_KEY_NOT_NEEDED, "CKF_RESTORE_KEY_NOT_NEEDED")
    ; (_CKF_CLOCK_ON_TOKEN, "CKF_CLOCK_ON_TOKEN")
    ; (_CKF_PROTECTED_AUTHENTICATION_PATH, "CKF_PROTECTED_AUTHENTICATION_PATH")
    ; (_CKF_DUAL_CRYPTO_OPERATIONS, "CKF_DUAL_CRYPTO_OPERATIONS")
    ; (_CKF_TOKEN_INITIALIZED, "CKF_TOKEN_INITIALIZED")
    ; (_CKF_SECONDARY_AUTHENTICATION, "CKF_SECONDARY_AUTHENTICATION")
    ; (_CKF_USER_PIN_COUNT_LOW, "CKF_USER_PIN_COUNT_LOW")
    ; (_CKF_USER_PIN_FINAL_TRY, "CKF_USER_PIN_FINAL_TRY")
    ; (_CKF_USER_PIN_LOCKED, "CKF_USER_PIN_LOCKED")
    ; (_CKF_USER_PIN_TO_BE_CHANGED, "CKF_USER_PIN_TO_BE_CHANGED")
    ; (_CKF_SO_PIN_COUNT_LOW, "CKF_SO_PIN_COUNT_LOW")
    ; (_CKF_SO_PIN_FINAL_TRY, "CKF_SO_PIN_FINAL_TRY")
    ; (_CKF_SO_PIN_LOCKED, "CKF_SO_PIN_LOCKED")
    ; (_CKF_SO_PIN_TO_BE_CHANGED, "CKF_SO_PIN_TO_BE_CHANGED") ]
  in

  let session_info =
    [ (_CKF_RW_SESSION, "CKF_RW_SESSION")
    ; (_CKF_SERIAL_SESSION, "CKF_SERIAL_SESSION") ]
  in

  let any = [(_CKF_ARRAY_ATTRIBUTE, "CKF_ARRAY_ATTRIBUTE")] in

  let mechanism_info =
    [ (_CKF_HW, "CKF_HW")
    ; (_CKF_ENCRYPT, "CKF_ENCRYPT")
    ; (_CKF_DECRYPT, "CKF_DECRYPT")
    ; (_CKF_DIGEST, "CKF_DIGEST")
    ; (_CKF_SIGN, "CKF_SIGN")
    ; (_CKF_SIGN_RECOVER, "CKF_SIGN_RECOVER")
    ; (_CKF_VERIFY, "CKF_VERIFY")
    ; (_CKF_VERIFY_RECOVER, "CKF_VERIFY_RECOVER")
    ; (_CKF_GENERATE, "CKF_GENERATE")
    ; (_CKF_GENERATE_KEY_PAIR, "CKF_GENERATE_KEY_PAIR")
    ; (_CKF_WRAP, "CKF_WRAP")
    ; (_CKF_UNWRAP, "CKF_UNWRAP")
    ; (_CKF_DERIVE, "CKF_DERIVE")
    ; (_CKF_EC_F_P, "CKF_EC_F_P")
    ; (_CKF_EC_F_2M, "CKF_EC_F_2M")
    ; (_CKF_EC_ECPARAMETERS, "CKF_EC_ECPARAMETERS")
    ; (_CKF_EC_NAMEDCURVE, "CKF_EC_NAMEDCURVE")
    ; (_CKF_EC_UNCOMPRESS, "CKF_EC_UNCOMPRESS")
    ; (_CKF_EC_COMPRESS, "CKF_EC_COMPRESS")
    ; (_CKF_EXTENSION, "CKF_EXTENSION") ]
  in

  let initialize =
    [ (_CKF_LIBRARY_CANT_CREATE_OS_THREADS, "CKF_LIBRARY_CANT_CREATE_OS_THREADS")
    ; (_CKF_OS_LOCKING_OK, "CKF_OS_LOCKING_OK") ]
  in

  let wait_for_slot = [(_CKF_DONT_BLOCK, "CKF_DONT_BLOCK")] in

  let otp_signature_info =
    [ (_CKF_NEXT_OTP, "CKF_NEXT_OTP")
    ; (_CKF_EXCLUDE_TIME, "CKF_EXCLUDE_TIME")
    ; (_CKF_EXCLUDE_COUNTER, "CKF_EXCLUDE_COUNTER")
    ; (_CKF_EXCLUDE_CHALLENGE, "CKF_EXCLUDE_CHALLENGE")
    ; (_CKF_EXCLUDE_PIN, "CKF_EXCLUDE_PIN")
    ; (_CKF_USER_FRIENDLY_OTP, "CKF_USER_FRIENDLY_OTP") ]
  in

  [ (Info_domain, info)
  ; (Slot_info_domain, slot_info)
  ; (Token_info_domain, token_info)
  ; (Session_info_domain, session_info)
  ; (Mechanism_info_domain, mechanism_info)
  ; (Initialize_domain, initialize)
  ; (Wait_for_slot_domain, wait_for_slot)
  ; (OTP_signature_info_domain, otp_signature_info)
  ; (Any_domain, any) ]

let flags_of_domain domain =
  try List.assoc domain pretty_string_mappings with
  | Not_found -> []

let split_with_string domain flags : (t * string) list * t =
  let expected_flags = flags_of_domain domain in
  let (split_flags, remaining) =
    List.fold_left
      (fun ((expected_flags, remaining_flags) as acc) (flag, str) ->
        if get ~flag ~flags then
          let remaining_flags =
            logical_and remaining_flags (Unsigned.ULong.lognot flag)
          in
          let expected_flags = (flag, str) :: expected_flags in
          (expected_flags, remaining_flags)
        else
          acc)
      ([], flags) expected_flags
  in
  (List.rev split_flags, remaining)

let split domain flags : t list * t =
  let (flags, remaining) = split_with_string domain flags in
  (List.map fst flags, remaining)

let to_pretty_strings domain flags =
  let (flags, remaining) = split_with_string domain flags in
  let flags = List.map snd flags in
  if equal remaining empty then
    flags
  else
    flags
    @ [ Printf.sprintf "0x%Lx"
        @@ Int64.of_string
        @@ Unsigned.ULong.to_string remaining ]

let to_pretty_string domain flags =
  let flags = to_pretty_strings domain flags in
  match flags with
  | [] -> "(none)"
  | f -> String.concat " | " f

type has_value =
  { value : Yojson.Safe.t
  ; string : string }
[@@deriving of_yojson]

let of_yojson json =
  (* We know that [P11_ulong.to_yojson] does not produce [`Assoc]s. *)
  let actual_json =
    match has_value_of_yojson json with
    | Ok {value; _} -> value
    | Error _ -> json
  in
  P11_ulong.of_yojson actual_json

let to_yojson = to_json ?pretty:None
