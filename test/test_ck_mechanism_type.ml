open OUnit2

let test_v2_40 =
  let test code ctxt =
    let is_known =
      let open P11_mechanism_type in
      match Pkcs11_CK_MECHANISM_TYPE.view @@ Unsigned.ULong.of_int code with
      | CKM_CS_UNKNOWN _ -> false
      | _ -> true
    in
    let msg = Printf.sprintf "Mechanism type should be known: 0x%x" code in
    assert_bool msg is_known
  in
  "2.40 mechanisms" >:::
  [ "CKM_DSA_SHA224" >:: test 0x00000013
  ; "CKM_DSA_SHA256" >:: test 0x00000014
  ; "CKM_DSA_SHA384" >:: test 0x00000015
  ; "CKM_DSA_SHA512" >:: test 0x00000016
  ; "CKM_GOSTR3410_KEY_PAIR_GEN" >:: test 0x00001200
  ; "CKM_GOSTR3410" >:: test 0x00001201
  ; "CKM_GOSTR3410_WITH_GOSTR3411" >:: test 0x00001202
  ; "CKM_GOSTR3411" >:: test 0x00001210
  ; "CKM_GOSTR3411_HMAC" >:: test 0x00001211
  ; "CKM_GOSTR3411_HMAC" >:: test 0x00001211
  ; "CKM_AES_KEY_WRAP" >:: test 0x00002109
  ]

let suite =
  "CK_MECHANISM_TYPE" >:::
  [ test_v2_40
  ]
