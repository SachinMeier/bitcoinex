defmodule Bitcoinex.SilentPayments do
  @moduledoc """
  Cryptographic primitives for BIP-352 Silent Payments.

  https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki

  This module implements the key-derivation math a Silent Payments wallet or
  scanner builds on. It is intentionally **lean**: it does not select coins,
  parse transactions, extract input public keys from scriptSigs/witnesses,
  choose the lexicographically smallest outpoint, or drive the scan loop. The
  caller owns the transaction and supplies the already-summed keys, the chosen
  `outpoint_L`, and the output index `k`.

  All public functions return `{:ok, value}` or `{:error, reason}`.

  ## Notation

  Uppercase = public keys (`Point`), lowercase = private keys (`PrivateKey`),
  `·` = EC scalar multiplication, `G` = generator, `n` = curve order.

  The protocol uses three BIP-340 tagged hashes:

    * `BIP0352/Inputs`       — `input_hash/2`
    * `BIP0352/SharedSecret` — `shared_secret_tweak/2` (`t_k`)
    * `BIP0352/Label`        — `label_tweak/2`

  ## Pipeline

      # sender computes the per-output taproot key (see Bitcoinex.SilentPayments later PRs)
      {:ok, ih} = input_hash(outpoint_l, a_pub_sum)
      {:ok, ecdh} = shared_secret(a_priv_sum, b_scan, ih)
      {:ok, t_k} = shared_secret_tweak(ecdh, 0)
      # P_0 = B_spend + t_k·G
  """

  alias Bitcoinex.Utils
  alias Bitcoinex.Secp256k1
  alias Bitcoinex.Secp256k1.{Math, Params, Point, PrivateKey}

  @n Params.curve().n

  @input_tag "BIP0352/Inputs"
  @shared_secret_tag "BIP0352/SharedSecret"
  @label_tag "BIP0352/Label"

  @typedoc "A 36-byte outpoint: 32-byte txid (little-endian) followed by a 4-byte vout (little-endian)."
  @type outpoint :: <<_::288>>

  @doc """
  input_hash computes `hash_BIP0352/Inputs(outpoint_L || ser_P(A))` as a 32-byte scalar.

  `outpoint_L` is the lexicographically smallest 36-byte outpoint among the
  transaction's inputs (the caller selects it, e.g. with `Enum.min/1`). `A` is
  the sum of the input public keys.

  Fails if the resulting value is not a valid scalar (`0` or `>= n`).
  """
  @spec input_hash(outpoint(), Point.t()) :: {:ok, <<_::256>>} | {:error, String.t()}
  def input_hash(<<outpoint::binary-size(36)>>, %Point{} = a_sum_pubkey) do
    hash = Utils.tagged_hash(@input_tag, outpoint <> Point.sec(a_sum_pubkey))

    if valid_scalar?(hash) do
      {:ok, hash}
    else
      {:error, "input_hash is not a valid scalar"}
    end
  end

  def input_hash(_, _), do: {:error, "outpoint must be 36 bytes"}

  @doc """
  shared_secret computes the ECDH point `input_hash · scalar · point`.

    * sender passes `(a_sum_privkey, B_scan, input_hash)`
    * receiver passes `(b_scan_privkey, A, input_hash)`

  `input_hash` must be a pre-validated 32-byte scalar (as produced by
  `input_hash/2`). Both parties arrive at the same point. Fails if the result is
  the point at infinity (or the effective scalar reduces to zero).
  """
  @spec shared_secret(PrivateKey.t(), Point.t(), <<_::256>>) ::
          {:ok, Point.t()} | {:error, String.t()}
  def shared_secret(%PrivateKey{d: d}, %Point{} = point, <<input_hash::binary-size(32)>>) do
    scalar = Math.modulo(d * :binary.decode_unsigned(input_hash), @n)

    if scalar == 0 do
      {:error, "shared secret scalar is zero"}
    else
      secret = Math.multiply(point, scalar)

      if Point.is_inf(secret) do
        {:error, "shared secret is the point at infinity"}
      else
        {:ok, secret}
      end
    end
  end

  @doc """
  shared_secret_tweak computes the per-output tweak
  `t_k = hash_BIP0352/SharedSecret(ser_P(ecdh_secret) || ser_32(k))`.

  Fails if `t_k` is not a valid scalar (`0` or `>= n`).
  """
  @spec shared_secret_tweak(Point.t(), non_neg_integer()) ::
          {:ok, PrivateKey.t()} | {:error, String.t()}
  def shared_secret_tweak(%Point{} = ecdh_secret, k) when is_integer(k) and k >= 0 do
    tweak =
      Utils.tagged_hash(@shared_secret_tag, Point.sec(ecdh_secret) <> Utils.int_to_big(k, 4))

    if valid_scalar?(tweak) do
      PrivateKey.new(:binary.decode_unsigned(tweak))
    else
      {:error, "shared secret tweak t_k is not a valid scalar"}
    end
  end

  @doc """
  sum_input_privkeys sums the input private keys into the aggregate spend key `a`.

  Taproot keys (first argument) are negated to their even-Y form before summing,
  per BIP-352; all other eligible keys (second argument) are summed as-is. The
  sum is taken mod `n`, so an intermediate sum of zero is fine — only the final
  sum being zero is an error (and means no outputs can be produced).
  """
  @spec sum_input_privkeys([PrivateKey.t()], [PrivateKey.t()]) ::
          {:ok, PrivateKey.t()} | {:error, String.t()}
  def sum_input_privkeys(taproot, other) when is_list(taproot) and is_list(other) do
    with {:ok, taproot_even} <- force_even_all(taproot) do
      case taproot_even ++ other do
        [] ->
          {:error, "no input private keys"}

        keys ->
          sum =
            keys |> Enum.reduce(0, fn %PrivateKey{d: d}, acc -> acc + d end) |> Math.modulo(@n)

          if sum == 0 do
            {:error, "input private key sum is zero"}
          else
            PrivateKey.new(sum)
          end
      end
    end
  end

  @doc """
  sum_input_pubkeys sums the input public keys into the aggregate `A`.

  Taproot inputs are supplied as 32-byte x-only keys (first argument) and lifted
  to their even-Y point; all other eligible inputs are supplied as `Point`s
  (second argument). Addition is commutative, so input order does not matter. An
  intermediate point at infinity is fine — only the final sum being the point at
  infinity is an error (and means the transaction is skipped).
  """
  @spec sum_input_pubkeys([<<_::256>>], [Point.t()]) :: {:ok, Point.t()} | {:error, String.t()}
  def sum_input_pubkeys(taproot_xonly, other) when is_list(taproot_xonly) and is_list(other) do
    with {:ok, taproot_points} <- lift_all(taproot_xonly) do
      case taproot_points ++ other do
        [] ->
          {:error, "no input public keys"}

        [first | rest] ->
          sum = Enum.reduce(rest, first, fn p, acc -> Math.add(acc, p) end)

          if Point.is_inf(sum) do
            {:error, "input public key sum is the point at infinity"}
          else
            {:ok, sum}
          end
      end
    end
  end

  @doc """
  label_tweak computes the label scalar
  `hash_BIP0352/Label(ser_256(b_scan) || ser_32(m))`.

  `b_scan` is the receiver's scan **private** key. `m` is the label integer
  (`m = 0` is reserved for the change label). Fails if the tweak is not a valid
  scalar.
  """
  @spec label_tweak(PrivateKey.t(), non_neg_integer()) ::
          {:ok, PrivateKey.t()} | {:error, String.t()}
  def label_tweak(%PrivateKey{d: b_scan}, m) when is_integer(m) and m >= 0 do
    tweak = Utils.tagged_hash(@label_tag, Utils.int_to_big(b_scan, 32) <> Utils.int_to_big(m, 4))

    if valid_scalar?(tweak) do
      PrivateKey.new(:binary.decode_unsigned(tweak))
    else
      {:error, "label tweak is not a valid scalar"}
    end
  end

  @doc """
  label_point computes the label point `label_tweak(m)·G`.

  This is what a scanner precomputes and stores (keyed by `m`) to recognize
  labeled outputs. Always include `m = 0` (the change label) when scanning.
  """
  @spec label_point(PrivateKey.t(), non_neg_integer()) :: {:ok, Point.t()} | {:error, String.t()}
  def label_point(%PrivateKey{} = b_scan, m) do
    with {:ok, tweak} <- label_tweak(b_scan, m) do
      {:ok, PrivateKey.to_point(tweak)}
    end
  end

  # A 32-byte hash is a valid secp256k1 scalar when it is neither 0 nor >= n.
  # Note: PrivateKey.new/1 only rejects d >= n, so this guard is what enforces
  # the non-zero requirement before the callers build a PrivateKey from the hash.
  defp valid_scalar?(<<bytes::binary-size(32)>>) do
    i = :binary.decode_unsigned(bytes)
    i != 0 and i < @n
  end

  # Negate each taproot private key to its even-Y form. Short-circuits on error.
  defp force_even_all(keys) do
    keys
    |> Enum.reduce_while({:ok, []}, fn key, {:ok, acc} ->
      case Secp256k1.force_even_y(key) do
        %PrivateKey{} = k -> {:cont, {:ok, [k | acc]}}
        {:error, msg} -> {:halt, {:error, msg}}
      end
    end)
    |> case do
      {:ok, ks} -> {:ok, Enum.reverse(ks)}
      err -> err
    end
  end

  # Lift each 32-byte x-only key to its even-Y point. Short-circuits on error.
  defp lift_all(xonly_keys) do
    xonly_keys
    |> Enum.reduce_while({:ok, []}, fn xonly, {:ok, acc} ->
      case Point.lift_x(xonly) do
        {:ok, point} -> {:cont, {:ok, [point | acc]}}
        {:error, msg} -> {:halt, {:error, msg}}
      end
    end)
    |> case do
      {:ok, points} -> {:ok, Enum.reverse(points)}
      err -> err
    end
  end
end
