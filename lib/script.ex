defmodule Bitcoinex.Script do
	@moduledoc """
		a module for manipulating Bitcoin Scripts
	"""

	import Bitcoinex.Opcode

	alias Bitcoinex.Utils

	@type t :: %__MODULE__{
		s: list
	}

	@enforce_keys [
		:s
	]
	defstruct [:s]

	defp invalid_opcode_error(msg), do: {:error, "invalid opcode: #{msg}"}

	# defguard is_opcode_num(op) when :erlang.is_map_key(op, opcode_nums())
	# defguard is_opcode_atom(op) when :erlang.is_map_key(op, opcode_atoms())

	@spec new() :: t()
	def new, do: %__MODULE__{s: []}

	@spec is_true?(t()) :: bool
	def is_true?(%__MODULE__{s: [0x51]}), do: true
	def is_true?(%__MODULE__{s: [:op_true]}), do: true
	def is_true?(_), do: false


	@spec empty?(t()) :: bool
	def empty?(%__MODULE__{s: []}), do: true
	def empty?(_), do: false

	@spec get_op_num(atom) :: non_neg_integer()
	def get_op_num(op), do: Map.fetch(opcode_atoms(), op)

	@spec get_op_atom(non_neg_integer()) :: atom
	def get_op_atom(i), do: if i > 0 and i < 0x4c, do: i, else: Map.fetch(opcode_nums(), i) 

	@spec pop(t()) :: nil | {:ok, non_neg_integer(), t()}
	def pop(%__MODULE__{s: []}), do: nil
	def pop(%__MODULE__{s: [item | stack]}), do: {:ok, item, %__MODULE__{s: stack}}

	@spec push_op(atom | non_neg_integer(), t()) :: t()

	def push_op(%__MODULE__{s: stack}, item) do
		# item is opcode num
		if is_integer(item) and item > 0 and item < 0xff do
			%__MODULE__{s: [item | stack]}
		else
			# item is atom
			case get_op_num(item) do
				nil -> invalid_opcode_error(item)
				{:ok, op} -> %__MODULE__{s: [op | stack]}	
			end
		end
	end

	defp push_raw_data(%__MODULE__{s: stack}, data) do
		%__MODULE__{s: [data | stack]}
	end

	@spec push_data(binary, t()) :: t()
	def push_data(script, data) do
		datalen = byte_size(data)
		script = push_raw_data(script, data)
		cond do
			datalen < 0x4c ->
				push_op(script, datalen)
			datalen <= 0xff ->
				push_op(script, :op_pushdata1)
			datalen <= 0xffff ->
				push_op(script, :op_pushdata2)
			datalen <= 0xffffffff ->
				push_op(script, :op_pushdata4)
			true ->
				{:error, "invalid data length, must be 0..0xffffffff, got #{datalen}"}
		end
	end

	# SERIALIZE & PARSE 
	defp serializer(%__MODULE__{s: []}, acc), do: acc
	defp serializer(%__MODULE__{s: [item | script]}, acc) when is_integer(item) do
		serializer(%__MODULE__{s: script}, acc <> Utils.int_to_little(item, 1))
	end
	# For data pushes
	defp serializer(%__MODULE__{s: [item | script]}, acc) when is_binary(item) do
		len = byte_size(item)
		cond do
			len <= 0x4b -> # CHECK IF PUSHDATA75 is valid
				len = Utils.int_to_little(len, 1)
				serializer(%__MODULE__{s: script}, acc <> len <> item)
			len <= 0xff -> 
				len = Utils.int_to_little(len, 1)
				serializer(%__MODULE__{s: script}, acc <> len <> item)
			# PUSHDATA4 limited to 520 bytes
			len <= 0x0208->
				len = Utils.int_to_little(len, 2)
				serializer(%__MODULE__{s: script}, acc <> len <> item)
			true -> {:error, "data is too long"}
		end
	end

	def serialize(script) do
		script = serializer(script, <<>>)
		len = byte_size(script)
		Utils.encode_int(len) <> script
	end

	def to_hex(script) do
		 script
		 |> serialize() 
		 |> Base.encode16(case: :lower)
	end 

	def raw_combine(%__MODULE__{s: s1}, %__MODULE__{s: s2}), do: %__MODULE__{s: s1 ++ s2}
	
	def display(script) do
		" " <> scriptxt = display_script(script, "")
		scriptxt
	end

	defp display_script(%__MODULE__{s: []}, acc), do: acc
	defp display_script(%__MODULE__{s: [item | stack]}, acc) when is_integer(item) do
		if item > 0 and item < 0x4c do
			display_script(%__MODULE__{s: stack}, acc <> " OP_PUSHBYTES_#{item}")
		else
			{:ok, op_atom} = get_op_atom(item)
			upper_op = to_string(op_atom) |> String.upcase()
			display_script(%__MODULE__{s: stack}, acc <> " " <> upper_op ) 
		end
	end
	defp display_script(%__MODULE__{s: [item | stack]}, acc) when is_binary(item) do
		display_script(%__MODULE__{s: stack}, acc <> " " <> Base.encode16(item, case: :lower) ) 
	end

	#TODO to_address from address
	#TODO parse scripts

	# SCRIPT TYPE DETERMINERS

	def is_p2pkh(script) do
		try do
			{:ok, 0x76, script} = pop(script)
			{:ok, 0xa9, script} = pop(script)
			{:ok, 0x14, script} = pop(script)
			{:ok, <<_::binary-size(20)>>, script} = pop(script)
			{:ok, 0x88, script} = pop(script)
			{:ok, 0xac, script} = pop(script)
			empty(script)
		rescue 
			_ in MatchError -> false
		end
	end

	def is_p2sh(script) do
		try do
			{:ok, 0xa9, script} = pop(script)
			{:ok, 0x14, script} = pop(script)
			{:ok, <<_::binary-size(20)>>, script} = pop(script)
			{:ok, 0x87, script} = pop(script)
			empty(script)
		rescue 
			_ in MatchError -> false
		end
	end

	def is_p2wpkh(script) do
		try do
			{:ok, 0x00, script} = pop(script)
			{:ok, 0x14, script} = pop(script)
			{:ok, <<_::binary-size(20)>>, script} = pop(script)
			empty(script)
		rescue 
			_ in MatchError -> false
		end
		
	end

	def is_p2wsh(script) do
		try do
			{:ok, 0x00, script} = pop(script)
			{:ok, 0x20, script} = pop(script)
			{:ok, <<_::binary-size(32)>>, script} = pop(script)
			empty(script)
		rescue 
			_ in MatchError -> false
		end
	end

	# from bip340 https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#script-validation-rules
	def is_p2tr(script) do
		try do
			{:ok, 0x01, script} = pop(script)
			{:ok, <<_::binary-size(32)>>, script} = pop(script)
			empty(script)
		rescue 
			_ in MatchError -> false
		end
	end

	# CREATE COMMON SCRIPTS 

	def create_p2pkh(<<pkh::binary-size(20)>>) do
		new()
		|> push_op(0xac)
		|> push_op(0x88)
		|> push_data(pkh)
		|> push_op(0xa9)
		|> push_op(0x76)
	end
	def create_p2pkh(_), do: {:error, "pubkey hash must be a 20-byte hash"}

	def create_p2sh(<<sh::binary-size(20)>>) do
		new()
		|> push_op(0x87)
		|> push_data(sh)
		|> push_op(0xa9)
	end
	def create_p2sh(_), do: {:error, "script hash must be a 20-byte hash"}

	def create_witness_script(witver, witness_program) do
		new()
		|> push_data(witness_program)
		|> push_op(witver)
	end

	def create_p2wpkh(<<pkh::binary-size(20)>>) do: create_witness_script(0x00, pkh)
	def create_p2wpkh(_), do: {:error, "pubkey hash must be a 20-byte hash"}

	def create_p2wsh(<<sh::binary-size(32)>>) do: create_witness_script(0x00, sh)
	def create_p2wsh(_), do: {:error, "script hash must be a 32-byte hash"}

	def create_p2tr(<<pk::binary-size(32)>>), do: create_witness_script(0x01, pk)
	def create_p2tr(_), do: {:error, "public key must be 32-bytes"}

	
end