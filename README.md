# NfQueue

## Usage

```elixir
defmodule Example do
  @moduledoc false

  @nf_accept 1

  def start_link do
    NfQueue.start_link(_queue_id = 0, callback_mod: __MODULE__)
  end

  def nfq_init(_opts) do
    {}
  end
  
  def nfq_verdict(_family, info, state) do
    IO.puts "THIS IS NFQUEUE message!!!!"
    IO.inspect(info)
    {@nf_accept, _nfq_attrs = [mark: 0xabc] state}
  end
end
```

```elixir
THIS IS NFQUEUE message!!!!
[{:packet_hdr, 123229, 2048, 3}, {:ifindex_outdev, 1}, {:mark, 2748},
 {:ct,
  [tuple_orig: [ip: [v4_src: {127, 0, 0, 1}, v4_dst: {127, 0, 0, 53}],
    proto: [num: :udp, src_port: 33610, dst_port: 53]],
   tuple_reply: [ip: [v4_src: {127, 0, 0, 53}, v4_dst: {127, 0, 0, 1}],
    proto: [num: :udp, src_port: 53, dst_port: 33610]], id: 1834526272,
   status: [:dst_nat_done], timeout: 0]}, {:ct_info, :new},
 {:payload,
  <<69, 0, 0, 59, 243, 49, 64, 0, 64, 17, 73, 74, 127, 0, 0, 1, 127, 0, 0, 53,
    131, 74, 0, 53, 0, 39, 28, 148, 44, 182, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5,
    112, 114, 111, ...>>}]
```

## Verdict

- nf_drop:   0
- nf_accept: 1
- nf_stolen: 2
- nf_queue:  3
- nf_repeat: 4
- nf_stop:   5

## Supported NFQ attributes

- mark: 1..0xffffffff
- payload: binary()
- ct: term()
