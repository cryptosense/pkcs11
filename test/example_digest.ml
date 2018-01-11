let mechanisms =
  [ P11.Mechanism.CKM_MD5
  ; P11.Mechanism.CKM_SHA_1
  ; P11.Mechanism.CKM_SHA256
  ; P11.Mechanism.CKM_SHA384
  ; P11.Mechanism.CKM_SHA512
  ]

let print_digest driver session plaintext mechanism =
  let digest = P11_driver.digest driver session mechanism plaintext in
  let `Hex h = Hex.of_string digest in
  Printf.printf
    "Digest(%s, %S) = %S\n"
    (P11.Mechanism.to_string mechanism)
    plaintext
    h

let run ~dll ~slot_id ~pin ~plaintext =
  Pkcs11_log.set_logging_function prerr_endline;
  let driver =
    P11_driver.load_driver
      ?log_calls:None
      ?on_unknown:None
      ~dll
      ~use_get_function_list:`Auto
  in
  P11_driver.initialize driver;
  let slot =
    match P11_driver.get_slot driver slot_id with
    | Ok s -> s
    | Error e -> failwith e
  in
  let session =
    P11_driver.open_session
      driver
      ~slot
      ~flags:P11.Flags._CKF_SERIAL_SESSION
  in
  P11_driver.login driver session P11.User_type.CKU_USER pin;
  List.iter
    (print_digest driver session plaintext)
    mechanisms

let () =
  match Sys.argv with
  | [| _ ; dll ; slot_string ; pin ; plaintext |] ->
    let slot_id = P11.Slot.Index (int_of_string slot_string) in
    run ~dll ~slot_id ~pin ~plaintext
  | _ ->
      invalid_arg "Usage: digest <dll> <slot> <pin> <plaintext>"
