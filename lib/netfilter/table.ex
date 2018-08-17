defmodule Netfilter.Table do
  @moduledoc """
  nftable request abstruction interface
  """

  import Record

  for {name, schema} <- extract_all(from_lib: "gen_netlink/include/netlink.hrl") do
    defrecord(name, schema)
  end

  @netlink_netfilter 12

  def start_link do
    {:ok, _pid} = Netlink.Client.start_link(@netlink_netfilter)
  end

  def stop(pid) do
    Process.unlink(pid)
    Process.exit(pid, :kill)
  end

  # conntrack tables

  def get_conntrack(pid, attrs \\ []) do
    cmd = {:unspec, _version = 0, _resid = 0, attrs}
    Netlink.Client.ctnl_request(pid, :get, [:match, :root], cmd)
  end

  def set_conntrack(pid, attrs \\ []) do
    cmd = {:inet, _version = 0, _resid = 0, attrs}
    Netlink.Client.ctnl_request(pid, :new, [:create, :request, :ack, :excl], cmd)
  end

  def delete_conntrack(pid, attrs \\ []) do
    cmd = {:inet, _version = 0, _resid = 0, attrs}
    Netlink.Client.ctnl_request(pid, :delete, [:request, :ack], cmd)
  end

  # table

  def gettables(pid) do
    type = :gettable
    flags = [:match, :root]
    msg = {:unspec, 0, 0,[]}
    case Netlink.Client.nft_request(pid, type, flags, msg) do
      {:ok, tables0} ->
        {:ok, decode_result(tables0)}
      {:error, errno} ->
        {:error, errno}
    end
  end

  def newtable(pid, name), do: newtable(pid, :inet, name)

  def newtable(pid, family, name) do
    msg = {family, 0, 0, table_attributes(name: name, flags: [])}
    Netlink.Client.nft_blocking_request(pid, :newtable, [:create, :excl], msg)
  end

  def deltable(pid, name), do: deltable(pid, :inet, name)

  def deltable(pid, family, name) do
    msg = {family, 0, 0, table_attributes(name: name, flags: [])}
    Netlink.Client.nft_blocking_request(pid, :deltable, [:create, :excl], msg)
  end

  # chain

  def getchains(pid) do
    type = :getchain
    flags = [:match, :root]
    msg = {:unspec, 0, 0,[]}
    case Netlink.Client.nft_request(pid, type, flags, msg) do
      {:ok, chains0} ->
        {:ok, decode_result(chains0)}
      {:error, errno} ->
        {:error, errno}
    end
  end

  def newchain(pid, table, name, attr \\ []), do: newchain(pid, :inet, table, name, attr)

  def newchain(pid, family, table, name, attr0) do
    attr = chain_attributes([table: table, name: name] ++ attr0)
    msg = {family, 0, 0, Enum.uniq(attr)}
    Netlink.Client.nft_blocking_request(pid, :newchain, [:create, :excl], msg)
  end

  def delchain(pid, table, name), do: delchain(pid, :inet, table, name)

  def delchain(pid, family, table, name) do
    attr = chain_attributes(table: table, name: name)
    msg = {family, 0, 0, Enum.uniq(attr)}
    Netlink.Client.nft_blocking_request(pid, :delchain, [:create, :excl], msg)
  end

  # rule

  def getrules(pid) do
    type = :getrule
    flags = [:match, :root]
    msg = {:unspec, 0, 0,[]}
    case Netlink.Client.nft_request(pid, type, flags, msg) do
      {:ok, rules} ->
        {:ok, decode_result(rules)}
      {:error, errno} ->
        {:error, errno}
    end
  end

  def newrule(pid, table, chain, attr), do: newrule(pid, :inet, table, chain, attr)

  def newrule(pid, family, table, chain, attr0) do
    attr = rule_attributes(family, [table: table, chain: chain] ++ attr0)
    msg = {family, 0, 0, Enum.uniq(attr)}
    Netlink.Client.nft_blocking_request(pid, :newrule, [:create, :excl], msg)
  end

  def delrule(pid, table, chain, handle) do
    delrule(pid, :inet, table, chain, handle)
  end

  def delrule(pid, family, table, chain, handle) do
    msg = {family, 0, 0, rule_attributes(family, table: table, chain: chain, handle: handle)}
    Netlink.Client.nft_blocking_request(pid, :delrule, [], msg)
  end

  # set

  def getsets(pid) do
    type = :getset
    flags = [:match, :root]
    msg = {:unspec, 0, 0,[]}
    case Netlink.Client.nft_request(pid, type, flags, msg) do
      {:ok, sets} ->
        {:ok, decode_result(sets)}
      {:error, errno} ->
        {:error, errno}
    end
  end

  def newset(pid, table, name, attr), do: newset(pid, :inet, table, name, attr)

  def newset(pid, family, table, name, attr0) do
    attr = set_attributes([table: table, name: name] ++ attr0)
    msg = {family, 0, 0, Enum.uniq(attr)}
    Netlink.Client.nft_blocking_request(pid, :newset, [:create, :excl], msg)
  end

  def delset(pid, table, name), do: delset(pid, :inet, table, name)

  def delset(pid, family, table, name) do
    attr = set_attributes(table: table, name: name)
    msg = {family, 0, 0, attr}
    Netlink.Client.nft_blocking_request(pid, :delset, [], msg)
  end

  # set element

  def getsetelem(pid) do
    type = :getsetelem
    flags = [:match, :root]
    msg = {:unspec, 0, 0,[]}
    Netlink.Client.nft_request(pid, type, flags, msg)
  end

  def newsetelem(pid, attr) do
    msg = {:inet, 0, 0, attr}
    Netlink.Client.nft_blocking_request(pid, :newsetelem, [:create, :excl], msg)
  end

  def delsetelem(pid, name) do
    msg = {:inet, 0, 0, name: name}
    Netlink.Client.nft_blocking_request(pid, :delsetelem, [:create, :excl], msg)
  end

  # private functions

  defp decode_result(tables), do: decode_result([], tables)

  defp decode_result(acc, []), do: Enum.reverse(acc)

  defp decode_result(acc, [nftables(type: :newtable, msg: msg)|rest]) do
    {family, _version, _resid, attrs} = msg
    decode_result([{family, table_attributes(attrs)}|acc], rest)
  end
  defp decode_result(acc, [nftables(type: :newchain, msg: msg)|rest]) do
    {family, _version, _resid, attrs} = msg
    decode_result([{family, chain_attributes(attrs)}|acc], rest)
  end
  defp decode_result(acc, [nftables(type: :newrule, msg: msg)|rest]) do
    {family, _version, _resid, attrs} = msg
    decode_result([{family, rule_attributes(family, attrs)}|acc], rest)
  end
  defp decode_result(acc, [nftables(type: :newset, msg: msg)|rest]) do
    {family, _version, _resid, attrs} = msg
    decode_result([{family, set_attributes(attrs)}|acc], rest)
  end

  ##
  ## rule utilities
  ##

  defp set_attributes(attrs), do: set_attributes([], attrs)

  defp set_attributes(acc, []), do: Enum.reverse(acc)
  defp set_attributes(acc, [{k, v}|rest]) do
    set_attributes([{k, set_attr_value(k, v)}|acc], rest)
  end

  defp set_attr_value(:table, name) when is_binary(name), do: to_charlist(name)
  defp set_attr_value(:table, name) when is_list(name), do: to_string(name)
  defp set_attr_value(:name, name) when is_binary(name), do: to_charlist(name)
  defp set_attr_value(:name, name) when is_list(name), do: to_string(name)
  defp set_attr_value(:key_type, <<keytype::32>>), do: keytype
  defp set_attr_value(:key_type, keytype), do: <<keytype::32>>
  defp set_attr_value(:data_type, <<datatype::32>>), do: datatype
  defp set_attr_value(:data_type, datatype), do: <<datatype::32>>
  defp set_attr_value(_k, v), do: v

  ##
  ## rule utilities
  ##

  defp rule_attributes(family, attrs), do: rule_attributes([], attrs, family)

  defp rule_attributes(acc, [], _family), do: Enum.reverse(acc)
  defp rule_attributes(acc, [{k, v}|rest], family) do
    rule_attributes([{k, rule_attr_value(family, k, v)}|acc], rest, family)
  end

  defp rule_attr_value(family, :expressions, exprs) do
    try do
      exprs
      |> Enum.map(&:netlink_codec.nft_decode(family, &1))
    rescue
      _e ->
        exprs
        |> Enum.map(&:netlink_codec.nft_encode(family, &1))
    end
  end
  defp rule_attr_value(_family, :table, name) when is_binary(name), do: to_charlist(name)
  defp rule_attr_value(_family, :table, name) when is_list(name), do: to_string(name)
  defp rule_attr_value(_family, :chain, name) when is_binary(name), do: to_charlist(name)
  defp rule_attr_value(_family, :chain, name) when is_list(name), do: to_string(name)
  defp rule_attr_value(_family, _k, v), do: v

  ##
  ## table utilities
  ##

  defp table_attributes(attrs), do: table_attributes([], attrs)

  defp table_attributes(acc, []), do: Enum.reverse(acc)
  defp table_attributes(acc, [{k, v}|rest]),
    do: table_attributes([{k, table_attr_value(k, v)}|acc], rest)

  defp table_attr_value(:name, name) when is_binary(name), do: to_charlist(name)
  defp table_attr_value(:name, name) when is_list(name), do: to_string(name)
  defp table_attr_value(_k, v), do: v

  ##
  ## chain utilities
  ##

  defp chain_attributes(attrs), do: chain_attributes([], attrs)

  defp chain_attributes(acc, []), do: Enum.reverse(acc)
  defp chain_attributes(acc, [{k, v}|rest]),
    do: chain_attributes([{k, chain_attr_value(k, v)}|acc], rest)

  defp chain_attr_value(:name, name) when is_binary(name), do: to_charlist(name)
  defp chain_attr_value(:name, name) when is_list(name), do: to_string(name)
  defp chain_attr_value(:table, table) when is_binary(table), do: to_charlist(table)
  defp chain_attr_value(:table, table) when is_list(table), do: to_string(table)
  defp chain_attr_value(:type, type) when is_binary(type), do: to_charlist(type)
  defp chain_attr_value(:type, type) when is_list(type), do: to_string(type)
  defp chain_attr_value(:hook, hook), do: chain_hook_attributes([], hook)
  defp chain_attr_value(_k, v), do: v

  defp chain_hook_attributes(acc, []), do: Enum.reverse(acc)
  defp chain_hook_attributes(acc, [{k, v}|rest]),
    do: chain_hook_attributes([{k, chain_hook_attr_value(k, v)}|acc], rest)

  defp chain_hook_attr_value(:dev, dev) when is_binary(dev), do: to_charlist(dev)
  defp chain_hook_attr_value(:dev, dev) when is_list(dev), do: to_string(dev)
  defp chain_hook_attr_value(:hooknum, dev), do: chain_hook_hooknum(dev)
  defp chain_hook_attr_value(_k, v), do: v

  defp chain_hook_hooknum(:prerouting),  do: 0
  defp chain_hook_hooknum(:input),       do: 1
  defp chain_hook_hooknum(:forward),     do: 2
  defp chain_hook_hooknum(:postrouting), do: 3
  defp chain_hook_hooknum(:output),      do: 4
  defp chain_hook_hooknum(:ingress),     do: 5

  defp chain_hook_hooknum(0),     do: :prerouting
  defp chain_hook_hooknum(1),     do: :input
  defp chain_hook_hooknum(2),     do: :forward
  defp chain_hook_hooknum(3),     do: :postrouting
  defp chain_hook_hooknum(4),     do: :output
  defp chain_hook_hooknum(5),     do: :ingress
  defp chain_hook_hooknum(other), do: other
end
