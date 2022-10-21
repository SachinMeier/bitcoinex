alias Bitcoinex.LightningNetwork.Invoice

# invoice, amount -> pubkey, amount
getpk = fn [inv_str, amt] -> {:ok, inv} = Invoice.decode(inv_str); [inv.destination, amt] end

# write pubkey,amouunt to CSV file
{:ok, file} = File.open("es-withdrawal-destinations-aug25.csv", [:write])
writepk = fn [pubkey, amt] -> IO.binwrite(file, pubkey <> "," <> amt <> "\n") end

"scripts/es-wds-aug25.csv"
|> Path.expand(__DIR__)
|> File.stream!()
|> Stream.map(&String.trim/1)
|> Stream.map(getpk)
|> Stream.map(writepk)
|> Stream.run

csv =  "scripts/es-wds-aug25.csv"
|> Path.expand(__DIR__)
|> File.stream!()
|> Stream.drop(1) #drop headers
|> Stream.map(&String.trim/1)
|> CSV.decode!()
|> Stream.map(getpk)
|> Stream.map(writepk)
|> Stream.run
