defmodule NfQueue do
  use GenServer

  defmodule State do
    defstruct [
      socket:   nil,
      queue:    nil,
      cb_mod:   nil,
      cb_state: nil
    ]
  end

  require Logger

  @netlink_netfilter 12
  @nfqnl_copy_packet 2
  @nf_accept 1

  def nfq_init(_options), do: nil

  def nfq_verdict(_family, info, state) do
    IO.inspect(info)
    {@nf_accept, state}
  end

  def start_link(queue, opts \\ []) do
    GenServer.start_link(__MODULE__, [queue, opts])
  end

  def init([queue, opts]) do
    callback_mod = opts[:callback_mod] || __MODULE__
    {:ok, socket} = :gen_socket.socket(:netlink, :raw, @netlink_netfilter)
    :ok = :gen_socket.bind(socket, netlink_sockaddr_nl())
    :ok = :gen_socket.setsockopt(socket, :sol_socket, :rcvbuf, 57_108_864)
    :ok = :gen_socket.setsockopt(socket, :sol_socket, :sndbuf, 57_108_864)
    :ok = nfq_create_queue(socket, queue)
    :ok = nfq_set_mode(socket, queue, @nfqnl_copy_packet, 0xffff)
    :ok = nfq_set_flags(socket, queue, [:conntrack], [:conntrack])
    :ok = :gen_socket.input_event(socket, true)
    cb_state = callback_mod.nfq_init(opts)
    {:ok, %State{socket: socket, queue: queue, cb_mod: callback_mod, cb_state: cb_state}}
  end

  def handle_info({socket, :input_ready}, %State{socket: socket} = state) do
    case :gen_socket.recv(socket, 8192) do
      {:ok, data} ->
        data
        |> :netlink_codec.nl_ct_dec
        |> Enum.each(&send(self(), &1))
      other ->
        :ok = Logger.debug("[#{__MODULE__}] other: #{inspect(other)}")
    end
    :ok = :gen_socket.input_event(socket, true)
    {:noreply, state}
  end
  def handle_info({:queue, :packet, _flags, _seq, _pid, packet}, state) do
    new_state = process_nfq_packet(packet, state)
    {:noreply, new_state}
  end
  def handle_info(_info, state) do
    {:noreply, state}
  end

  # private functions

  defp nfq_create_queue(socket, queue),
    do: build_send_cfg_msg(socket, :bind, queue, :unspec)

  defp nfq_set_mode(socket, queue, copy_mode, length) do
    command = {:params, length, copy_mode}
    message = {:queue, :config, [:ack, :request], 0, 0, {:unspec, 0, queue, [command]}}
    nfnl_query(socket, message)
  end

  defp nfq_set_flags(socket, queue, flags, mask) do
    command = [mask: mask, flags: flags]
    message = {:queue, :config, [:ack, :request], 0, 0, {:unspec, 0, queue, command}}
    nfnl_query(socket, message)
  end

  defp build_send_cfg_msg(socket, command, queue, pf) do
    command = {:cmd, command, pf}
    message = {:queue, :config, [:ack, :request], 0, 0, {:unspec, 0, queue, [command]}}
    nfnl_query(socket, message)
  end

  defp nfnl_query(socket, query) do
    request = :netlink_codec.nl_ct_enc(query)
    :gen_socket.sendto(socket, netlink_sockaddr_nl(), request)
    case :gen_socket.recv(socket, 8192) do
      {:ok, reply} ->
        case :netlink_codec.nl_ct_dec(reply) do
          [{:netlink, :error, _, _, _, {0, _}}|_]     -> :ok
          [{:netlink, :error, _, _, _, {errno, _}}|_] -> {:error, errno}
          [msg|_] -> {:error, msg}
          other   -> other
        end
      other ->
        other
    end
  end

  defp process_nfq_packet({family, _version, _queue, info}, state)
  when family == :inet or family == :inet6 do
    %State{socket: socket, queue: queue, cb_mod: cb_mod, cb_state: cb_state} = state
    {nla, new_cb_state} = do_callback(family, info, cb_mod, cb_state)
    message = {:queue, :verdict, [:request], 0, 0, {:unspec, 0, queue, nla}}
    request = :netlink_codec.nl_ct_enc(message)
    :gen_socket.sendto(socket, netlink_sockaddr_nl(), request)
    %{state|cb_state: new_cb_state}
  end
  defp process_nfq_packet({_family, _version, queue, info}, state) do
    {_, id, _, _} = :lists.keyfind(:packet_hdr, 1, info)
    nla = [{:verdict_hdr, @nf_accept, id}]
    message = {:queue, :verdict, [:request], 0, 0, {:unspec, 0, queue, nla}}
    request = :netlink_codec.nl_ct_enc(message)
    :gen_socket.sendto(state.socket, netlink_sockaddr_nl(), request)
    state
  end

  defp do_callback(family, info, cb_mod, cb_state) do
    {_, id, _, _} = :lists.keyfind(:packet_hdr, 1, info)
    case cb_mod.nfq_verdict(family, info, cb_state) do
      {verdict, attrs, new_cb_state} when is_list(attrs) ->
        {[{:verdict_hdr, verdict, id}|attrs], new_cb_state}
      {verdict, new_cb_state} ->
        {[{:verdict_hdr, verdict, id}], new_cb_state}
      _ ->
        {[{:verdict_hdr, @nf_accept, id}], cb_state}
    end
  end

  # mesosphere/gen_netlink.sockaddr_nl/3 is not defined.
  defp netlink_sockaddr_nl do
    sockaddr_nl(:netlink, 0, 0)
  end

  defp sockaddr_nl(family, pid, groups) do
    sockaddr_nl({family, pid, groups})
  end

  defp sockaddr_nl({family, pid, groups}) when is_atom(family) do
    sockaddr_nl({:gen_socket.family(family), pid, groups})
  end
  defp sockaddr_nl({family, pid, groups}) do
    <<family::16-native-integer, 0::16, pid::32-native-integer, groups::32-native-integer>>
  end
  defp sockaddr_nl(<< family::16-native-integer, _pad::16, pid::32-native-integer, groups::32-native-integer>>) do
    {:gen_socket.family(family), pid, groups}
  end
end
