# Netlink

## Installation

Add `:netlink` as a dependency to your project's `mix.exs`:

```elixir
defp deps do
  [{:netlink, git: "https://gh.iiji.jp/Stratosphere/netlink", branch: "develop"}]
end
```

## Usage

### Netlink.Route functions

this module can be Linux network setup via rtnl.

- start_link/0
- stop/1
- iplink\_add/4, iplink\_add/5
- iplink_del/2
- iplink_set/3
- ipaddr_replace/4
- ipaddr_show/2
- ipneigh_replace/4
- ipneigh_del/4
- iproute_replace/5
- iproute\_add\_with\_dev/4, iproute\_add\_with\_dev/5
- iproute_del/5
- bridge\_fdb\_append/4
- bridge\_fdb\_del/4
- iprule\_add/3, iprule\_add/4

#### Example

```elixir
{:ok, pid} = Netlink.Route.start_link
{:ok, []} = Netlink.Route.iplink_add(pid, "vxlan0", "vxlan", 5, 4789)
{:ok, []} = Netlink.Route.iplink_set(pid, "vxlan0", address: <<0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff>>)
{:ok, []} = Netlink.Route.ipaddr_replace(pid, {192,168,5,1}, 24, "vxlan0")
{:ok, {{192,168,5,1}, 24}} = Netlink.Route.ipaddr_show(pid, "vxlan0")
{:ok, []} = Netlink.Route.ipneigh_replace(pid, {99,99,99,99}, "00faceb00c", "docker0")
{:ok, []} = Netlink.Route.iproute_replace(pid, {100,100,100,0}, 24, {172,18,0,1})
{:ok, []} = Netlink.Route.iproute_add_with_dev(pid, {200,200,200,0}, 24, 8)
{:ok, []} = Netlink.Route.bridge_fdb_append(pid, {200,200,200,200}, "00cafebabe", "vxlan0")
{:ok, []} = Netlink.Route.iprule_add(pid, 0, 1, [fwmark: 1, fwmask: 1])
```

### Netfilter.Queue

Callback module must implement `module.nfq_init/1` and `module.nfq_verdict/3`, like the following example:

#### Example

```elixir
defmodule Example do
  @moduledoc false

  @nf_accept 1

  def start_link do
    Netfilter.Queue.start_link(_queue_id = 0, callback_mod: __MODULE__)
  end

  def nfq_init(_opts) do
    {}
  end
  
  def nfq_verdict(_family, info, state) do
    IO.puts "THIS IS NFQUEUE message!!!!"
    IO.inspect(info)
    {@nf_accept, _nfq_attrs = [mark: 0xabc], state}
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

#### Verdict:

- nf_drop:   0
- nf_accept: 1
- nf_stolen: 2
- nf_queue:  3
- nf_repeat: 4
- nf_stop:   5

#### Supported NFQ attributes:

- mark:           `1..0xffffffff`
- label:          `1..0xffffffff`
- payload:        `binary()`
- ct:             `term()`
- ifindex_indev:  `non_neg_integer()`
- ifindex_outdev: `non_neg_integer()`
- hwaddr:         `<<_::6-bytes>>`
