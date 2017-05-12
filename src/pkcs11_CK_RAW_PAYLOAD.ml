type t = Pkcs11_CK_MECHANISM_TYPE.t * string

let make params =
  let open P11_raw_payload_params in
  ( Pkcs11_CK_MECHANISM_TYPE.make params.mechanism
  , params.data
  )

let view (raw_mechanism_type, raw_data) =
  let open P11_raw_payload_params in
  { mechanism = Pkcs11_CK_MECHANISM_TYPE.view raw_mechanism_type
  ; data = raw_data
  }

let compare a b =
  P11_raw_payload_params.compare (view a) (view b)
