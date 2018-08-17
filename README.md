# Netlink

## Installation

Add `:netlink` as a dependency to your project's `mix.exs`:

```elixir
defp deps do
  [{:netlink, github: "shun159/netlink", branch: "develop"}]
end
```

## Usage

### Netlink.Event functions

- subscribe/1
- stop/1

```elixir
> {:ok, pid} = Netlink.Event.subscribe(:rtnetlink)
> flush()
> _ = Netlink.Event.stop(pid)
```

- event types:
  - :rtnetlink
  - :ctnetlink

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
- iprule\_del/3, iprule\_del/4

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
{:ok, []} = Netlink.Route.iprule_add(pid, _prefix_len = 0, _table = 1, fwmark: 1, fwmask: 1)
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

### Netfilter.Table

nftables intarface.  
Implemented functions in this module are follows:

```elixir
{:ok, pid} = Netfilter.Table.start_link
Netfilter.Table.stop(pid)
```

#### Connection tracking

- get\_conntrack/1, get\_conntrack/2
- set\_conntrack/1, set\_conntrack/2

##### Examples:

```elixir
{:ok, entries} = Netfilter.Table.get_conntrack(pid)
{:ok, []} = Netfilter.Table.set_conntrack(pid, 
  timeout:     3,
  tuple_orig:  [ip: [v4_src: {192,168,5,25}, v4_dst: {192,168,5,128}], proto: [num: :icmp, icmp_id: 12102, icmp_type: 8, icmp_code: 0]],
  tuple_reply: [ip: [v4_dst: {192,168,5,25}, v4_src: {192,168,5,128}], proto: [num: :icmp, icmp_id: 12102, icmp_type: 0, icmp_code: 0]]
)

attrs = 
  pid
  |> Netfilter.Table.get_conntrack()
  |> Kernel.elem(1)
  |> Enum.at(0)
  |> Kernel.elem(5)
  |> Kernel.elem(3)
  |> Enum.filter(fn({key, _v}) -> key in [:tuple_orig, :tuple_reply] end)

{:ok, []} = Netfilter.Table.delete_conntrack(pid, attrs)
```

#### Table-related

- gettables/1
- newtable/2, newtable/3
- deltable/2, deltable/3

##### Examples:

```elixir
{:ok, tables} = Netfilter.Table.gettables(pid)
{:ok, []} = Netfilter.Table.newtable(pid, "foo")
{:ok, []} = Netfilter.Table.newtable(pid, _family = :inet6, "foo6")
{:ok, []} = Netfilter.Table.deltable(pid, "foo")
{:ok, []} = Netfilter.Table.deltable(pid, _family = :inet6, "foo6")
```

##### Types:

- family: `:inet | :inet6`

#### Chain-related

- getchains/1
- newchain/3, newchain/4, newchain/5
- delchain/3, delchain/4

##### Examples:

```elixir
{:ok, chains} = Netfilter.Table.getchains(pid)
{:ok, []} = Netfilter.Table.newchain(pid, _table = "foo", _name  = "blah",
  policy: :accept,
  type: "nat",
  hook: [hooknum: :prerouting, priority: 0]
)
{:ok, []} = Netfilter.Table.delchain(pid, "foo", "blah")
```

##### Chain Attributes

- handle: `0..0xffffffffffffffff`
- hook: `nft_chain_hook_attrs()`
- policy: `:drop | :accept, | :stolen | :queue | :repeat | :stop`
- type: `"filter" | "nat" | "route"`
- `nft_chain_hook_attrs()`
  - hooknum: `:prerouting | :input | :forward | :postrouting | :output | :ingress`
  - priority: `0..0xffffffff`
  - dev: `String.t`

#### Rule-related

- getrules/1
- newrule/4, newrule/5
- delrule/4, delrule/5

##### Examples

```elixir
{:ok, rules} = Netfilter.Table.getrules(pid)
{:ok, []} = Netfilter.Table.newrule(pid,
  _table = "foo",
  _chain = "blah",
   expressions: [
     expr: [name: 'payload', data: [dreg: 1, base: :network_header, offset: 12, len: 4]],
     expr: [
       name: 'bitwise',
       data: [sreg: 1, dreg: 1, len: 4, mask: [value: <<255, 255, 255, 224>>], xor: [value: <<0, 0, 0, 0>>]]
     ],
     expr: [name: 'cmp', data: [sreg: 1, op: :eq, data: [value: <<10, 5, 6, 0>>]]],
     expr: [name: 'meta', data: [key: :oif, dreg: 1]],
     expr: [name: 'cmp', data: [sreg: 1, op: :eq, data: [value: <<15, 0, 0, 0>>]]],
     expr: [name: 'masq', data: ""]
   ]
)
{:ok, []} = Netfilter.Table.delrule(pid, "foo", "postrouting", _handle = 15)
```

Above is equivalent to below....(´；ω；`)

```
table ip foo {
  chain postrouting {
    ip saddr 10.5.6.0/27 oif "veth0" masquerade
　}
}
```

#### Set-related

- getsets/1
- newset/4, newset/5 # newset/4 and /5 doen't work
- delset/3, delset/4

##### Examples

```elixir
{:ok, rules} = Netfilter.Table.getsets(pid)
Netfilter.Table.newset(pid, _table = "foo", _name = "blahblah",
  flags: [:timeout],
  key_type: 13,
  key_len: 2,
  timeout: 10845000,
  userdata: "",
  desc: ""
)
{:ok, []} = Netfilter.Table.delset(pid, "foo", "blahblah")
```

#### Setelement-related
