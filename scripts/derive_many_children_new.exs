{:ok, file} = File.open("addresses-external-hw1.txt", [:write])
{:ok, xpub} = Bitcoinex.ExtendedKey.parse_extended_key("xpub6DQPF8e2L83rNc3k3QWpjSAPo2UD7DRhvKQ3d8X86sokEFQx8qi6TidS6ahTG9qek4tUhKRQ5iT35tep77rq9kf1phWmamEfUvuQRndXCC9")
for i <- 1..1360 do

{:ok, xkey} = Bitcoinex.ExtendedKey.derive_extended_key(xpub, %Bitcoinex.ExtendedKey.DerivationPath{child_nums: [0, i]})
{:ok, pub} = Bitcoinex.ExtendedKey.to_public_key(xkey)
{:ok, s} = Bitcoinex.Script.public_key_to_p2wpkh(pub)
{:ok, addr} = Bitcoinex.Script.to_address(s, :mainnet)
IO.binwrite(file, addr <> "\n")
end
