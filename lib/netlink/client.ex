###-------------------------------------------------------------------
### @author sdhillon, shun159
### @copyright (C) 2016, Mesosphere, Inc. 2017 Internet Initiative Japan, Inc.
### @doc
###
### @end
### Created : 10. Oct 2016 5:16 PM
###-------------------------------------------------------------------

defmodule Netlink.Client do
  @behaviour :gen_statem

  defmodule Data do
    @moduledoc """
    Defines NetFilter.Client data structure
    """
    defstruct [
      socket:       nil,
      fd:           nil,
      pid:          nil,
      seq:          0,
      last_rq_from: nil,
      replies:      nil,
      cur_seq:      nil,
      family:       nil,
      mon_ref:      nil
    ]
  end

  defmodule Counter do
    @moduledoc """
    Counter
    """

    def start_link(init \\ 0),
      do: Agent.start_link(fn -> init end)

    def current(agent),
      do: Agent.get(agent, fn(count) -> count end)

    def increment(agent, incr \\ 1),
      do: Agent.update(agent, &(&1 + incr))

    def cur_and_incr(agent, incr \\ 1) do
      cur = current(agent)
      :ok = increment(agent, incr)
      cur
    end
  end

  import Record

  defrecord :request,      [:family, :cmd, :flags, :msg]
  defrecord :rtnl_request, [:type, :flags, :msg]
  defrecord :ctnl_request, [:type, :flags, :msg]
  defrecord :nft_request,  [:type, :flags, :msg]

  for {name, schema} <- extract_all(from_lib: "gen_netlink/include/netlink.hrl") do
    defrecord(name, schema)
  end

  @eth_p_ip 0x0800

  def request(pid, family, command, msg),
    do: request(pid, family, command, [], msg)
  def request(pid, family, command, flags, msg),
    do: :gen_statem.call(pid, request(family: family, cmd: command, flags: flags, msg: msg), 5000)

  def rtnl_request(pid, type, msg),
    do: rtnl_request(pid, type, [], msg)
  def rtnl_request(pid, type, flags, msg),
    do: :gen_statem.call(pid, rtnl_request(type: type, flags: flags, msg: msg), 5000)

  def ctnl_request(pid, type, msg),
    do: ctnl_request(pid, type, [], msg)
  def ctnl_request(pid, type, flags, msg),
    do: :gen_statem.call(pid, ctnl_request(type: type, flags: flags, msg: msg), 5000)

  def ctnl_blocking_request(pid, type, msg),
    do: ctnl_request(pid, type, [], msg)
  def ctnl_blocking_request(pid, type, flags, msg),
    do: :gen_statem.call(pid, {:blocking, ctnl_request(type: type, flags: flags, msg: msg)}, 5000)

  def nft_request(pid, type, msg),
    do: nft_request(pid, type, [], msg)
  def nft_request(pid, type, flags, msg),
    do: :gen_statem.call(pid, nft_request(type: type, flags: flags, msg: msg), 5000)

  def nft_blocking_request(pid, type, msg),
    do: nft_blocking_request(pid, type, [], msg)
  def nft_blocking_request(pid, type, flags, msg),
    do: :gen_statem.call(pid, {:blocking, nft_request(type: type, flags: flags, msg: msg)}, 5000)

  def if_nametoindex(ifname) do
    options = get_options(:packet, @eth_p_ip, :raw)
    if_nametoindex(ifname, options)
  end

  def callback_mode, do: [:handle_event_function]

  def start_link(family_id),
    do: :gen_statem.start_link(__MODULE__, [family_id], [])

  def init([family_id]),
    do: {:ok, IDLE, init_data(family_id)}

  def handle_event(event, request, IDLE, data),
    do: handle_IDLE(event, request, data)
  def handle_event(event, msg, WAIT, data),
    do: handle_WAIT(event, msg, data)
  def handle_event(:info, msg, _state, data),
    do: handle_SIGNAL(msg, data)

  def terminate(_reason, _state, %Data{fd: fd}),
    do: _ = :procket.close(fd)

  # private functions

  defp handle_IDLE({:call, from}, request, data) do
    new_data = handle_request(from, request, data)
    {:next_state, WAIT, new_data}
  end

  defp handle_WAIT(:internal, {:nl_msg, msg}, data),
    do: handle_message(msg, data)
  defp handle_WAIT(:info, {socket, {:data, packet}}, %Data{socket: socket} = data),
    do: handle_packet(packet, data)

  defp handle_SIGNAL({:DOWN, ref, :process, _pid, _reason}, %Data{mon_ref: ref}),
    do: {:stop, :port_monitor_failed}
  defp handle_SIGNAL(_, %Data{}),
    do: :keep_state_and_data

  defp handle_request(from, request(family: family) = msg, data) do
    %Data{socket: socket} = data
    {message, cur_seq} = build_message(msg, data)
    send_command(socket, codec(family, message))
    %{data|last_rq_from: from, replies: [], cur_seq: cur_seq}
  end
  defp handle_request(from, {:blocking, msg}, data) do
    %Data{socket: socket, family: family} = data

    begin_msg = request(family: family, cmd: :begin, flags: [:request], msg: <<2,0,10,0>>)
    end_msg = request(family: family, cmd: :end, flags: [:request], msg: <<2,0,10,0>>)

    {begin_message, _cur_seq} = build_message(begin_msg, data)
    {message, cur_seq} = build_message(msg, data)
    {end_message, _cur_seq} = build_message(end_msg, data)

    begin_msg_binary = codec(family, begin_message)
    msg_binary = codec(family, message)
    end_msg_binary = codec(family, end_message)

    send_command(socket, <<begin_msg_binary::bytes, msg_binary::bytes, end_msg_binary::bytes>>)

    %{data|last_rq_from: from, replies: [], cur_seq: cur_seq}
  end
  defp handle_request(from, msg, data) do
    %Data{socket: socket, family: family} = data
    {message, cur_seq} = build_message(msg, data)
    send_command(socket, codec(family, message))
    %{data|last_rq_from: from, replies: [], cur_seq: cur_seq}
  end

  defp handle_packet(packet, %Data{family: family}) do
    next_actions = family
    |> codec(packet)
    |> Enum.map(&{:next_event, :internal, {:nl_msg, &1}})
    {:keep_state_and_data, next_actions}
  end

  defp handle_message(netlink(type: type, seq: cur_seq) = msg, %Data{cur_seq: cur_seq} = data)
  when type in [:done, :error] do
    process_reply(msg, data)
    {:next_state, IDLE, %{data|last_rq_from: nil, replies: [], cur_seq: nil}}
  end
  defp handle_message(netlink(seq: cur_seq) = msg, %Data{cur_seq: cur_seq} = data) do
    %Data{replies: replies} = data
    {:keep_state, %{data|replies: [msg|replies]}}
  end

  defp handle_message(rtnetlink(type: type, seq: cur_seq) = msg, %Data{cur_seq: cur_seq} = data)
  when type in [:done, :error] do
    process_reply(msg, data)
    {:next_state, IDLE, %{data|last_rq_from: nil, replies: [], cur_seq: nil}}
  end
  defp handle_message(rtnetlink(seq: cur_seq) = msg, %Data{cur_seq: cur_seq} = data) do
    %Data{replies: replies} = data
    {:keep_state, %{data|replies: [msg|replies]}}
  end

  defp handle_message(ctnetlink(type: type, seq: cur_seq) = msg, %Data{cur_seq: cur_seq} = data)
  when type in [:done, :error] do
    process_reply(msg, data)
    {:next_state, IDLE, %{data|last_rq_from: nil, replies: [], cur_seq: nil}}
  end
  defp handle_message(ctnetlink(seq: cur_seq) = msg, %Data{cur_seq: cur_seq} = data) do
    %Data{replies: replies} = data
    {:keep_state, %{data|replies: [msg|replies]}}
  end

  defp handle_message(nftables(type: type, seq: cur_seq) = msg, %Data{cur_seq: cur_seq} = data)
  when type in [:done, :error] do
    process_reply(msg, data)
    {:next_state, IDLE, %{data|last_rq_from: nil, replies: [], cur_seq: nil}}
  end
  defp handle_message(nftables(seq: cur_seq) = msg, %Data{cur_seq: cur_seq} = data) do
    %Data{replies: replies} = data
    {:keep_state, %{data|replies: [msg|replies]}}
  end

  defp process_reply(_, %Data{last_rq_from: from}) when not is_tuple(from),
    do: throw(:inconsistent_state)
  defp process_reply(message, %Data{last_rq_from: from, replies: replies}),
    do: :gen_statem.reply(from, build_reply(message, replies))

  defp build_reply(netlink(type: :done), replies),
    do: {:ok, Enum.reverse(replies)}
  defp build_reply(netlink(type: :error, msg: {0, _payload}), replies),
    do: {:ok, Enum.reverse(replies)}
  defp build_reply(netlink(type: :error, msg: {errno, _payload}), replies),
    do: {:error, errno, Enum.reverse(replies)}
  defp build_reply(rtnetlink(type: :done), replies),
    do: {:ok, Enum.reverse(replies)}
  defp build_reply(rtnetlink(type: :error, msg: {0, _payload}), replies),
    do: {:ok, Enum.reverse(replies)}
  defp build_reply(rtnetlink(type: :error, msg: {errno, _payload}), replies),
    do: {:error, errno, Enum.reverse(replies)}
  defp build_reply(ctnetlink(type: :done), replies),
    do: {:ok, Enum.reverse(replies)}
  defp build_reply(ctnetlink(type: :error, msg: {0, _payload}), replies),
    do: {:ok, Enum.reverse(replies)}
  defp build_reply(ctnetlink(type: :error, msg: {errno, _payload}), replies),
    do: {:error, errno, Enum.reverse(replies)}

  defp build_message(
    nft_request(type: type, flags: flags0, msg: msg),
    %Data{pid: pid, seq: seq}) do
    flags = prepend_flag(flags0)
    seq = Counter.cur_and_incr(seq)
    message = nftables(
      type: type,
      flags: flags,
      seq: seq,
      pid: pid,
      msg: msg
    )
    {message, seq}
  end
  defp build_message(
    rtnl_request(type: type, flags: flags0, msg: msg),
    %Data{pid: pid, seq: seq}) do
    flags = prepend_flag(flags0)
    seq = Counter.cur_and_incr(seq)
    message = rtnetlink(
      type: type,
      flags: flags,
      seq: seq,
      pid: pid,
      msg: msg
    )
    {message, seq}
  end
  defp build_message(
    ctnl_request(type: type, flags: flags0, msg: msg),
    %Data{pid: pid, seq: seq}) do
    flags = prepend_flag(flags0)
    seq = Counter.cur_and_incr(seq)
    message = ctnetlink(
      type: type,
      flags: flags,
      seq: seq,
      pid: pid,
      msg: msg
    )
    {message, seq}
  end
  defp build_message(
    request(cmd: command, flags: flags0, msg: msg),
    %Data{pid: pid, seq: seq}) do
    flags = prepend_flag(flags0)
    seq = Counter.cur_and_incr(seq)
    message = netlink(
      type: command,
      flags: flags,
      seq: seq,
      pid: pid,
      msg: msg
    )
    {message, seq}
  end

  defp codec(family, binary) when is_binary(binary) do
    family
    |> family_name
    |> :netlink_codec.nl_dec(binary)
  end
  defp codec(family, msg) when is_tuple(msg) do
    family
    |> family_id
    |> :netlink_codec.nl_enc(msg)
  end

  defp get_options(family, family_id, type),
    do: [family: family, protocol: family_id, type: type]

  defp send_command(socket, msg),
    do: _ = Port.command(socket, msg)

  defp prepend_flag(flags),
    do: Enum.uniq([:request, :ack] ++ flags)

  defp family_id({:generic, id, _name}), do: id
  defp family_id(family) when is_integer(family), do: family
  defp family_name({:generic, _id, name}), do: name
  defp family_name(family), do: family

  defp init_data(family_id) do
    options = get_options(:netlink, family_id, :dgram)
    {fd, socket, mon_ref} = init_port(options)
    pid = List.to_integer(:os.getpid)
    {:ok, seq} = Counter.start_link
    %Data{fd: fd, socket: socket, pid: pid, family: family_id, mon_ref: mon_ref, seq: seq}
  end

  defp init_port(options) do
    {:ok, fd} = :procket.open(0, options)
    port = Port.open({:fd, fd, fd}, [:binary])
    monitor_ref = :erlang.monitor(:port, port)
    {fd, port, monitor_ref}
  end

  defp if_nametoindex(ifname, options) do
    {:ok, fd} = :procket.open(0, options)
    try do
      case :packet.ifindex(fd, ifname) do
        index when is_integer(index) and index >= 0 -> {:ok, index}
      end
    catch
      error ->
        {:error, error}
    after
      :procket.close(fd)
    end
  end
end
