module type PKCS = sig
  type t
  type u
  val make : u -> t
  val view : t -> u
  val to_string : u -> string
  val of_string : string -> u
  val equal : u -> u -> bool
  val compare : u -> u -> int
end
