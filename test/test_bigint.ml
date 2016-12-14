open OUnit2

let test_decode ctxt =
  let testcase s n =
    let expected = P11.Bigint.of_int n in
    let got = P11.Bigint.decode s in
    let cmp = P11.Bigint.equal in
    let printer = P11.Bigint.to_string in
    assert_equal ~cmp ~printer expected got
  in
  testcase "\x12\x34\x56\x78" 0x12_34_56_78;
  let u_max_int = P11.Bigint.decode "\x40\x00\x00\x00\x00\x00\x00\x00" in
  assert_raises Z.Overflow (fun () -> P11.Bigint.to_int u_max_int);
  testcase "\x00\x00\x00\x12\x34\x56\x78" 0x12_34_56_78;
  testcase "" 0

let test_encode ctxt =
  let testcase n s =
    let expected = s in
    let u = P11.Bigint.of_int n in
    let got = P11.Bigint.encode u in
    let printer x =
      let `Hex h = Hex.of_string x in
      h
    in
    assert_equal ~printer expected got
  in
  testcase 0x12_34_56_78 "\x12\x34\x56\x78"

let suite =
  "Bigint" >:::
  [ "Decoding" >:: test_decode
  ; "Encoding" >:: test_encode
  ]
