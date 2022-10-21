alias Bitcoinex.{ExtendedKey, Script}

{:ok, file} = File.open("scripts/data/lnd-platform-1-addrs.csv", [:write])

_rn1_zpub_str = "zpub6s4urTyrdV8p5CRyi8659cMQ8xm6zTQhkYSVBvJtrtZWLT3QeA3Dhqwi8zcdFy9VZM86CGcX13A8rTswYWgrkE2DZNuckase2P2hCtMd8Pk"
_rn2_zpub_str = "zpub6rGRpDY94JkHftD8zyh4SvJDbF35KBPxQVpJEEHKqXh9dWJMrJdTwKGhoCeV4hSxt9DkktVza1Tx4A8HEgFYw8f7g5n3f65NvF2V3rRUxUw"
lp1_zpub_str = "zpub6qzeXzPgvkwUYmcDa8CJFjW2Z9CCJSFL6CEPxHfspfQwbNkryYs5c423WAPmdsRxJC3BE9WsEh7iWnDbX6sQ3xhgVptWcyNYRJEJRBW5bpr"


{:ok, zpub} = ExtendedKey.parse_extended_key(lp1_zpub_str)

for i <- 1..5 do
  deriv = %Bitcoinex.ExtendedKey.DerivationPath{child_nums: [0, i]}
  {:ok, deriv_str} = Bitcoinex.ExtendedKey.DerivationPath.to_string(deriv)
  {:ok, xkey} = ExtendedKey.derive_extended_key(zpub, deriv)
  {:ok, pub} = ExtendedKey.to_public_key(xkey)
  {:ok, s} = Script.public_key_to_p2wpkh(pub)
  {:ok, addr} = Script.to_address(s, :mainnet)

  IO.binwrite(file, deriv_str <> ", " <> addr <> "\n")
end
