open OUnit2

let test_hash_template ctx =
  let pack a v = P11.Attribute.Pack (a,v) in
  let template =
    P11.Attribute_type.[
      pack CKA_VERIFY true;
      pack CKA_WRAP true;
      pack CKA_VALUE (Hex.to_string (`Hex "f0204dac4a96a391"));
      pack CKA_MODIFIABLE true;
      pack CKA_ALWAYS_SENSITIVE false;
      pack CKA_NEVER_EXTRACTABLE false;
      pack CKA_LOCAL true;
      pack CKA_EXTRACTABLE true;
      pack CKA_DERIVE false;
      pack CKA_SIGN true;
      pack CKA_UNWRAP true;
      pack CKA_DECRYPT true;
      pack CKA_ENCRYPT true;
      pack CKA_SENSITIVE false;
      pack CKA_ID "";
      pack CKA_KEY_TYPE P11.Key_type.CKK_DES;
      pack CKA_LABEL "1";
      pack CKA_PRIVATE false;
      pack CKA_TOKEN true;
      pack CKA_CLASS P11.Object_class.CKO_SECRET_KEY;
    ]
  in
  let rev_template = List.rev template in
  let hash = P11.Template.hash template in
  let hex_hash = Digest.to_hex hash in
  assert_equal ~cmp:[%eq: string] ~printer:[%show: string]
    "55aa7ba6c64a5147b8c98e17a8289bb2"
    hex_hash;
  let rev_hash = P11.Template.hash rev_template in
  let hex_rev_hash = Digest.to_hex rev_hash in
  assert_equal ~cmp:[%eq: string] ~printer:[%show: string]
    "55aa7ba6c64a5147b8c98e17a8289bb2"
    hex_rev_hash

let suite =
  "p11_template" >::: [
    "test_hash_template" >:: test_hash_template;
  ]
