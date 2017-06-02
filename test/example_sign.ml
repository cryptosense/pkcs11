(**
   Sign data using a key on a PKCS#11 token.

   Arguments are:
   - the PKCS#11 DLL to load. Example: /usr/lib/opencryptoki/libopencryptoki.so.0
   - a slot ID. Example: 0
   - a PIN. Example: 1234
   - a key label. Example: signkey
   - a plaintext path. Example: file.txt

   This will load the DLL, initialize it, find a private key with requested
   label, sign the plaintext using RSA-RSS with SHA-512, and display the
   resulting hex-encoded signature.

   To create the key pair, one can use:

   pkcs11-tool --module DLL -l -k --key-type rsa:2048 -a LABEL
*)

let key_template ~key_label =
  [
    P11.Attribute.Pack (P11.Attribute_type.CKA_LABEL, key_label);
    P11.Attribute.Pack (P11.Attribute_type.CKA_CLASS, P11.Object_class.CKO_PRIVATE_KEY);
  ]

let sign_mechanism =
  let params = P11.RSA_PKCS_PSS_params.{
      hashAlg = P11.Mechanism_type.CKM_SHA512;
      mgf = P11.RSA_PKCS_MGF_type._CKG_MGF1_SHA512;
      sLen = Unsigned.ULong.of_int 64;
    }
  in
  P11.Mechanism.CKM_SHA512_RSA_PKCS_PSS params

let read_file ~path =
  let ic = Pervasives.open_in path in
  let size = Pervasives.in_channel_length ic in
  let contents = Pervasives.really_input_string ic size in
  close_in ic;
  contents

let get_singleton = function
  | [x] -> Ok x
  | l -> Error (List.length l)

let run ~dll ~slot_id ~pin ~key_label ~plaintext =
  Pkcs11_log.set_logging_function prerr_endline;
  let (module S) =
    P11_driver.load_driver
      ?log_calls:None
      ?on_unknown:None
      ~dll
      ~use_get_function_list:`Auto
  in
  S.initialize ();
  let slot = match S.get_slot slot_id with
    | Ok s -> s
    | Error e -> failwith e
  in
  let session = S.open_session ~slot ~flags:P11.Flags._CKF_SERIAL_SESSION in
  S.login session P11.User_type.CKU_USER pin;
  let key =
    match get_singleton @@ S.find_objects session (key_template ~key_label) with
    | Ok k -> k
    | Error n -> failwith (Printf.sprintf "Expecting exactly one key, got %d" n)
  in
  let signature = S.sign session sign_mechanism key plaintext in
  let `Hex h = Hex.of_string signature in
  print_endline h

let () =
  match Sys.argv with
  | [| _ ; dll ; slot_string ; pin ; key_label ; plaintext_path |] ->
    let plaintext = read_file ~path:plaintext_path in
    let slot_id = P11.Slot.Index (int_of_string slot_string) in
    run ~dll ~slot_id ~pin ~key_label ~plaintext
  | _ ->
      invalid_arg "Usage: sign <dll> <slot> <pin> <key_label> <plaintext_path>"
