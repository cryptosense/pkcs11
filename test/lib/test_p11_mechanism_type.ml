open OUnit2

let test_encode_decode =
  "test encode decode"
  >:::
  let test expected ctxt =
    let encode_decode =
      P11_mechanism_type.of_string (P11_mechanism_type.to_string expected)
    in
    assert_equal ~ctxt ~cmp:P11_mechanism_type.equal
      ~printer:P11_mechanism_type.show expected encode_decode
  in
  List.map
    (fun t ->
      (Printf.sprintf "[%s]") (P11_mechanism_type.to_string t) >:: test t)
    P11_mechanism_type.elements

let suite = "P11_mechanism" >::: [test_encode_decode]
