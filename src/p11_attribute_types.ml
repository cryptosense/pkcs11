type t = P11_attribute_type.pack list [@@deriving yojson]
let rec mem: type a . t -> a P11_attribute_type.t -> bool = fun template x ->
  match template with
    | [] -> false
    | head :: tail ->
        match head with
          | P11_attribute_type.Pack ty ->
              match Pkcs11.CK_ATTRIBUTE_TYPE.compare' ty x with
                | Pkcs11.CK_ATTRIBUTE_TYPE.Equal -> true
                | Pkcs11.CK_ATTRIBUTE_TYPE.Not_equal _ -> mem tail x

let rec remove_duplicates l acc =
  match l with
    | [] -> List.rev acc
    | (P11_attribute_type.Pack ty as p)::q ->
        if mem acc ty
        then remove_duplicates q acc
        else remove_duplicates q (p::acc)

(** compares two normalized types list  *)
let rec compare a b =
  match a,b with
    | [], [] -> 0
    | [], _::_ -> -1
    | _::_, [] -> 1
    | a1::a2, b1::b2 ->
        let cmp = P11_attribute_type.compare_pack a1 b1 in
        if cmp = 0
        then compare a2 b2
        else cmp

let remove_duplicates l = remove_duplicates l []
