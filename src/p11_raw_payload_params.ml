type t = Pkcs11.CK_RAW_PAYLOAD.t

type record =
  { mechanism: P11_mechanism_type.t
  ; data: Pkcs11_hex_data.t
  }
[@@deriving yojson]

let to_yojson (ckm, data) =
  let mechanism = Pkcs11.CK_MECHANISM_TYPE.view ckm in
  record_to_yojson { mechanism ; data }

let of_yojson json =
  let open Ppx_deriving_yojson_runtime in
  record_of_yojson json >>= fun { mechanism ; data } ->
  let mechanism_type = Pkcs11.CK_MECHANISM_TYPE.make mechanism in
  Ok (mechanism_type, data)
