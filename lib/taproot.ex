defmodule Bitcoinex.Taproot do
  alias Bitcoinex.Utils

  alias Bitcoinex.Secp256k1
  alias Bitcoinex.Secp256k1.{Math, Params, Point, PrivateKey}
  alias Bitcoinex.Script

  @n Params.curve().n

  @bip342_leaf_version 0xc0

  @type tapnode :: {tapnode, tapnode} | TapLeaf.t() | nil

  @spec tweak_privkey(PrivateKey.t(), binary) :: PrivateKey.t() | {:error, String.t()}
  def tweak_privkey(sk0 = %PrivateKey{}, h) do
    sk = Secp256k1.force_even_y(sk0)
    case PrivateKey.to_point(sk) do
      {:error, msg} ->
        {:error, msg}

      pk ->
        t =
          Point.x_bytes(pk) <> h
          |> tagged_hash_taptweak()
          |> :binary.decode_unsigned()
        if t > @n do
          {:error, "invalid tweaked key"}
        else
          %PrivateKey{d: Math.modulo(sk.d + t, @n)}
        end
    end
  end

  @spec tweak_pubkey(Point.t(), binary) :: Point.t() | {:error, String.t()}
  def tweak_pubkey(pk = %Point{}, h) do
    t =
      Point.x_bytes(pk) <> h
      |> tagged_hash_taptweak()
      |> :binary.decode_unsigned()
    if t > @n do
      {:error, "invalid tweaked key"}
    else
      t_point = PrivateKey.to_point(t)
      Math.add(pk, t_point)
    end
  end


  @spec tagged_hash_tapbranch(binary) :: binary
  def tagged_hash_tapbranch(br), do: Utils.tagged_hash("TapBranch", br)

  @spec tagged_hash_taptweak(binary) :: binary
  def tagged_hash_taptweak(root), do: Utils.tagged_hash("TapTweak", root)

  @spec tagged_hash_tapleaf(binary) :: binary
  def tagged_hash_tapleaf(leaf), do: Utils.tagged_hash("TapLeaf", leaf)



  defmodule TapLeaf do
    @type tapleaf :: %__MODULE__{
      version: non_neg_integer(),
      script: Script.t()
    }
    @enforce_keys [
      :version,
      :script
    ]
    defstruct [
      :version,
      :script
    ]
  end

  # todo fix
  def merkelize_script_tree(nil), do: {nil, <<>>}
  def merkelize_script_tree(leaf = %TapLeaf{}) do
    hash =
      leaf.version
      |> :binary.encode_unsigned()
      |> Kernel.<>(Script.serialize_script(leaf.script))
      |> tagged_hash_tapleaf()

    {{left: leaf, right: nil}, hash}
  end

  def merkelize_script_tree(node = {left, right}) do
    {{l_branch, l_hash},
    {r_branch, r_hash}} =
      {merkelize_script_tree(left),
      merkelize_script_tree(right)}

    node =

    # combine the branches to form root node. I dont
    # get what this python means:
    # from: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
    # ret = [(l, c + right_h) for l, c in left] + [(l, c + left_h) for l, c in right]

    {l_h, r_h} = Utils.lexicographical_sort(l_h, r_h)
    hash = tagged_hash_tapbranch(l_h <> r_h)
    {node, hash}

  end


end
