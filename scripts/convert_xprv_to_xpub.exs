

xprv_str = "tprv..."
{:ok, xprv} = Bitcoinex.ExtendedKey.parse_extended_key(xprv_str)
{:ok, xpub} = Bitcoinex.ExtendedKey.to_extended_public_key(xprv)
Bitcoinex.ExtendedKey.display_extended_key(xpub)
