alias Bitcoinex.{Secp256k1, ExtendedKey, Script, Utils}
alias Bitcoinex.Secp256k1.{Point, Signature}
use Bitwise, only_operators: true

extracted_pk_str = "03384c80f696c291d65fff40fa1d951165e5b848ac56598f99e32a135a11c1846e"
real_pk_str = "03a8c35503a2c27ee8251efc66fbc45911f3e92273974b86e7c1bc9c08db59e5c1"

{:ok, extracted_pk} = Point.parse_public_key extracted_pk_str
{:ok, real_pk} = Point.parse_public_key real_pk_str

sig_str_b64 = "HwWNyQZev6Dr1Vn74igyoJz8Wk98HPlRXDpMES3TPGRzeNRKNbcfrHKb8BMWoZO1bQO0mi7VxKxkD/501VOkNt4="
sig1_bytes = Base.decode64!(sig_str_b64) |> :binary.part(0, 64)
{:ok, sig1} = Base.decode64!(sig_str_b64) |> :binary.part(0, 64) |> Signature.parse_signature
sig2_bytes = Base.decode64!(sig_str_b64) |> :binary.part(1, 64)
{:ok, sig2} = Base.decode64!(sig_str_b64) |> :binary.part(1, 64) |> Signature.parse_signature # this shouldnt work
recovery_id = Base.decode64!(sig_str_b64) |> :binary.part(0, 1) |> :binary.decode_unsigned()

msg = "BPM_Audit_FY2021"
msg_sha256_bytes = Utils.sha256(msg)
msg_double_sha256_bytes = Utils.double_sha256(msg)
msg_sha256 = msg_sha256_bytes |> :binary.decode_unsigned
msg_double_sha256 = msg_double_sha256_bytes |> :binary.decode_unsigned

Secp256k1.verify_signature real_pk, msg_sha256, sig1
Secp256k1.verify_signature real_pk, msg_double_sha256, sig1
Secp256k1.verify_signature real_pk, msg_sha256, sig2
Secp256k1.verify_signature real_pk, msg_double_sha256, sig2
Secp256k1.verify_signature extracted_pk, msg_sha256, sig1
Secp256k1.verify_signature extracted_pk, msg_double_sha256, sig1
Secp256k1.verify_signature extracted_pk, msg_sha256, sig2
Secp256k1.verify_signature extracted_pk, msg_double_sha256, sig2

Secp256k1.ecdsa_recover_compact msg_sha256_bytes, sig1_bytes, recovery_id
Secp256k1.ecdsa_recover_compact msg_double_sha256_bytes, sig1_bytes, recovery_id
Secp256k1.ecdsa_recover_compact msg_sha256_bytes, sig2_bytes, recovery_id
Secp256k1.ecdsa_recover_compact msg_double_sha256_bytes, sig2_bytes, recovery_id
Secp256k1.ecdsa_recover_compact msg_sha256_bytes, sig1_bytes, 0
Secp256k1.ecdsa_recover_compact msg_sha256_bytes, sig1_bytes, 1
Secp256k1.ecdsa_recover_compact msg_double_sha256_bytes, sig2_bytes, 0
Secp256k1.ecdsa_recover_compact msg_double_sha256_bytes, sig2_bytes, 1

Secp256k1.ecdsa_recover_compact msg_double_sha256_bytes, sig2_bytes, 27
Secp256k1.ecdsa_recover_compact msg_double_sha256_bytes, sig2_bytes, 28
Secp256k1.ecdsa_recover_compact msg_double_sha256_bytes, sig2_bytes, 1

Secp256k1.ecdsa_recover_compact msg_double_sha256_bytes, sig2_bytes, 1

Secp256k1.ecdsa_recover_compact msg_double_sha256_bytes, sig2_bytes, 1

for n <- 27..34, do: [n, Secp256k1.ecdsa_recover_compact(msg_double_sha256_bytes, sig1_bytes, n)]
for n <- 27..34, do: [n, Secp256k1.ecdsa_recover_compact(msg_sha256_bytes, sig1_bytes, n)]
for n <- 27..34, do: [n, Secp256k1.ecdsa_recover_compact(msg_sha256_bytes, sig2_bytes, n)]
for n <- 27..34, do: [n, Secp256k1.ecdsa_recover_compact(msg_double_sha256_bytes, sig2_bytes, n)]

# 27 uncompressed public key, y-parity 0, magnitude of x lower than the curve order
# 28 uncompressed public key, y-parity 1, magnitude of x lower than the curve order
# 29 uncompressed public key, y-parity 0, magnitude of x greater than the curve order
# 30 uncompressed public key, y-parity 1, magnitude of x greater than the curve order
# 31 compressed public key, y-parity 0, magnitude of x lower than the curve order
# 32 compressed public key, y-parity 1, magnitude of x lower than the curve order
# 33 compressed public key, y-parity 0, magnitude of x greater than the curve order
# 34 compressed public key, y-parity 1, magnitude of x greater than the curve order

recid = 31
{:ok, sig2} = Base.decode64!(sig_str_b64) |> :binary.part(1, 64) |> Signature.parse_signature
r = sig2.r
s = sig2.s

compr = (((recid - 0x1b) &&& 4) != 0)
recid = ((recid - 0x1b) &&& 3)
# if recid >= 2 do
#   r = r + Secp256k1.Params.curve().n
#   Secp256k1.ecdsa_recover_compact(msg_double_sha256_bytes, <<:binary.encode_unsigned(r), :binary.encode_unsigned(s)>>, recid)
# else
bin = :binary.encode_unsigned(r) <> :binary.encode_unsigned(s)
  Secp256k1.ecdsa_recover_compact(msg_double_sha256_bytes, bin, recid)
# end


# double check convert pubkey to address

# bill pubkey for #1
pk = "03a8c35503a2c27ee8251efc66fbc45911f3e92273974b86e7c1bc9c08db59e5c1"
{:ok, pubkey} = Point.parse_public_key pk
{:ok, script} = Script.public_key_to_p2pkh pubkey
{:ok, addr} = Script.to_address script, :mainnet

# // BILL
sigN = %Signature{
  s: 2512077101803655888456794845412438778121953887696714831030242481943623787635,
  r: 54652625585116999091796735991500098243998037897960279593199034593216234272478
}
Signature.der_serialize_signature(sigN) |> Base.encode16


# JONATHAN
sigJ = %Signature{
  s: 11639695816387077383880406583906137326471799538205110965892899912679602497669,
  r: 98251569137023810981822519434471602166214875452429960294538085581004246393661
}
Signature.der_serialize_signature(sigJ) |> Base.encode16
