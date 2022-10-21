
xpub = "xpub661MyMwAqRbcEiZgWU634oQ6upVF1QTCZBXU2o8rYS7cNYAVTwEKzbPLieQYhiLM4MgQN9xXEv9j7LY5nkdsuYagdNkgXCNhconisu6hYVr"
deriv_path = "0/0"

{:ok, xpub} = Bitcoinex.ExtendedKey.parse_extended_key(xpub)

for i <- 0..1350 do
  {:ok, dp} = Bitcoinex.ExtendedKey.DerivationPath.from_string(deriv_path)
  {:ok, xkey} = Bitcoinex.ExtendedKey.derive_extended_key(xpub, dp)
  {:ok, pub} = Bitcoinex.ExtendedKey.to_public_key(xkey)
  {:ok, s} = Bitcoinex.Script.public_key_to_p2wpkh(pub)
  {:ok, addr} = Bitcoinex.Script.to_address(s, :mainnet)
end
Bitcoinex.Point.serialize_public_key(pub)
