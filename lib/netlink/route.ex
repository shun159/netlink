defmodule Netlink.Route do
  use Bitwise

  import Record

  for {name, schema} <- extract_all(from_lib: "gen_netlink/include/netlink.hrl") do
    defrecord(name, schema)
  end

  @netlink_route 0
  @nud_noarp     0x40
  @nud_permanent 0x80

  def start_link do
    Netlink.Client.start_link(@netlink_route)
  end

  def stop(pid) do
    Process.unlink(pid)
    Process.exit(pid, :kill)
  end

  # ip link

  def iplink_add(pid, ifname, kind, id, dstport, dev) do
    linkinfo1 = iplink_linkinfo(kind, id, dstport)
    linkinfo = linkinfo1 ++ [link: Netlink.Utils.if_nametoindex(dev)]
    ifname = String.to_charlist(ifname)
    iplink(:add, pid, ifname: ifname, linkinfo: linkinfo)
  end

  def iplink_add(pid, ifname, kind, id, dstport) do
    linkinfo = iplink_linkinfo(kind, id, dstport)
    ifname = String.to_charlist(ifname)
    iplink(:add, pid, ifname: ifname, linkinfo: linkinfo)
  end

  def iplink_del(pid, ifname) do
    ifname = String.to_charlist(ifname)
    iplink(:del, pid, ifname: ifname)
  end

  def iplink_set(pid, ifname, attr) do
    attr = attr ++ [ifname: String.to_charlist(ifname)]
    iplink(:set, pid, attr)
  end

  # ip neigh

  def ipneigh_replace(pid, dst, lladdr, ifname) do
    ipneigh = ipneigh(ifname, dst, lladdr)
    netlink_request(pid, :newneigh, [:create, :replace], ipneigh)
  end

  def ipneigh_del(pid, dst, lladdr, ifname) do
    ipneigh = ipneigh(ifname, dst, lladdr)
    netlink_request(pid, :delneigh, [], ipneigh)
  end

  # ip addr

  def ipaddr_replace(pid, ipaddr, prefix_len, ifname) do
    ipaddr = ipaddr(prefix_len, ifname, local: ipaddr, address: ipaddr)
    netlink_request(pid, :newaddr, [:create, :replace], ipaddr)
  end

  def ipaddr_show(pid, ifname) do
    ipaddr = ipaddr(0, ifname)
    ifindex = Netlink.Utils.if_nametoindex(ifname)
    {:ok, addrs} = netlink_request(pid, :getaddr, [:match], ipaddr)
    case find_by_ifindex(ifindex, addrs) do
      {_family, prefix_len, _flags, _scope, _ifindex, attrs} ->
        addr = attrs[:address]
        {:ok, {addr, prefix_len}}
      other ->
        other
    end
  end

  # ip route

  def iproute_add_with_dev(pid, dst, prefix_len, ifname)
  when is_binary(ifname) do
    ifindex = Netlink.Utils.if_nametoindex(ifname)
    iproute_add_with_dev(pid, dst, prefix_len, ifindex)
  end
  def iproute_add_with_dev(pid, dst, prefix_len, ifindex, table_id \\ 32_766)
  when is_integer(ifindex) do
    do_iproute_replace(pid, prefix_len, table_id, dst: dst, oif: ifindex)
  end

  def iproute_replace(pid, dst, prefix_len, src, table_id \\ 32_766) do
    do_iproute_replace(pid, prefix_len, table_id, dst: dst, gateway: src)
  end

  def iproute_del(pid, dst, prefix_len, src, table_id \\ 32_766) do
    iproute = iproute(prefix_len, table_id, dst: dst, gateway: src)
    netlink_request(pid, :delroute, [], iproute)
  end

  # bridge fdb

  def bridge_fdb_append(pid, dst, lladdr, ifname) do
    neigh = bridge_fdb(ifname, dst, lladdr)
    netlink_request(pid, :newneigh, [:create, :append], neigh)
  end

  def bridge_fdb_del(pid, dst, lladdr, ifname) do
    neigh = bridge_fdb(ifname, dst, lladdr)
    netlink_request(pid, :delneigh, [], neigh)
  end

  # ip rule

  def iprule_add(pid, src_prefix_len, table, attr \\ []) do
    iprule = iprule(src_prefix_len, table, attr)
    netlink_request(pid, :newrule, [:create, :excl], iprule)
  end

  def iprule_del(pid, src_prefix_len, table, attr \\ []) do
    iprule = iprule(src_prefix_len, table, attr)
    netlink_request(pid, :delrule, [:create, :excl], iprule)
  end

  # private functions

  defp iplink(:add, pid, linkinfo) do
    link = iplink_link(linkinfo)
    netlink_request(pid, :newlink, [:create, :excl], link)
  end
  defp iplink(:del, pid, linkinfo) do
    link = iplink_link(linkinfo)
    netlink_request(pid, :dellink, [:excl], link)
  end
  defp iplink(:set, pid, attr) do
    link = iplink_link(attr)
    netlink_request(pid, :newlink, [], link)
  end

  defp iplink_link(attr) do
    {
      _family  = :inet,
      _type    = :arphrd_netrom,
      _ifindex = 0,
      _flags   = [1],
      _change  = [1],
      _attr    = attr
    }
  end

  defp iplink_linkinfo("vxlan", id, dstport) do
    vxlan = [
      id: id, ttl: 0, tos: 0, learning: 1, proxy: 0, rsc: 0,
      l2miss: 0, l3miss: 0, udp_csum: 0, udp_zero_csum6_tx: 0,
      udp_zero_csum6_rx: 0, remcsum_tx: 0, remcsum_rx: 0, port: dstport
    ]
    [kind: 'vxlan', data: vxlan]
  end

  defp ipneigh(ifname, dst, lladdr) do
    {
      _family   = :inet,
      _ifindex  = Netlink.Utils.if_nametoindex(ifname),
      _state    = @nud_permanent,
      _flags    = 0,
      _ndm_type = 0,
      _attr     = [dst: dst, lladdr: Netlink.Utils.mac_hex_to_tuple(lladdr)]
    }
  end

  defp ipaddr(prefix_len, ifname, attr \\ []) do
    {
      _family     = :inet,
      _prefix_len = prefix_len,
      _flags      = 0,
      _scope      = 0,
      _ifindex    = Netlink.Utils.if_nametoindex(ifname),
      _attr       = attr
    }
  end

  def do_iproute_replace(pid, prefix_len, table_id, attr) do
    iproute = iproute(prefix_len, table_id, attr)
    netlink_request(pid, :newroute, [:create, :replace], iproute)
  end

  defp iproute(prefix_len, table_id, attr) do
    {
      _family          = :inet,
      _dst_prefix_len  = prefix_len,
      _src_prefix_len  = 0,
      _type_of_service = 0,
      _table_id        = table_id,
      _protocol        = :boot,
      _scope           = :universe,
      _type            = :unicast,
      _flags           = [],
      _attr            = Enum.uniq(attr)
    }
  end

  defp bridge_fdb(ifname, dst, lladdr) do
    {
      _family   = :bridge,
      _ifindex  = Netlink.Utils.if_nametoindex(ifname),
      _state    = @nud_noarp ||| @nud_permanent,
      _flags    = 2, # ntf_self,
      _ndm_type = 0,
      _attr     = [dst: dst, lladdr: Netlink.Utils.mac_hex_to_tuple(lladdr)]
    }
  end

  defp iprule(src_prefix_len, table, attr) do
    {
      _family         = :inet,
      _dst_prefix_len = 0,
      _src_prefix_len = src_prefix_len,
      _tos            = 0,
      _table          = table,
      _protocol       = :boot,
      _scope          = :universe,
      _type           = :unicast,
      _flags          = [],
      _attr           = attr
    }
  end

  defp find_by_ifindex(ifindex, rtnetlinks) do
    case Enum.find(rtnetlinks, &filter_by_ifindex(&1, ifindex)) do
      nil                 -> :not_found
      rtnetlink(msg: msg) -> msg
    end
  end

  defp filter_by_ifindex(
    rtnetlink(
      type: :newlink,
      msg: {_family, _type, ifindex, _flags, _change, _attrs}
    ), ifindex) do
    true
  end
  defp filter_by_ifindex(
    rtnetlink(
      type: :newaddr,
      msg: {_family, _prefix_len, _flags, _scope, ifindex, _attrs}
    ), ifindex) do
    true
  end
  defp filter_by_ifindex(_, _) do
    false
  end

  defp netlink_request(pid, type, flags, msg),
    do: Netlink.Client.rtnl_request(pid, type, flags, msg)
end
