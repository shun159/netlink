defmodule Netlink.Event do
  @moduledoc """
  Netlink Event pusher
  """

  use Netlink.Consts

  defmodule State do
    @moduledoc false

    defstruct [
      subscriber: nil,
      mon_ref: nil,
      ct: nil,
      rt: nil,
    ]
  end

  def subscribe(type) do
    GenServer.start_link(__MODULE__, [type, self()])
  end

  def stop(pid) do
    GenServer.call(pid, :stop)
  end

  def init([type, subscriber]) do
    {:ok, ct_netlink} = socket(:netlink, :raw, @netlink_netfilter, [])
    :ok = bind_with_rcvbufsiz(ct_netlink)
    :ok = setsockopt_ct(ct_netlink)

    {:ok, rt_netlink} = socket(:netlink, :raw, @netlink_route, [])
    :ok = bind_with_rcvbufsiz(rt_netlink)
    :ok = setsockopt_rt(rt_netlink)

    mon_ref = Process.monitor(subscriber)

    state = %State{
      ct: ct_netlink,
      rt: rt_netlink,
      subscriber: {type, subscriber},
      mon_ref: mon_ref
    }
    {:ok, state}
    end

  def handle_call(:stop, _from, state) do
    {:stop, :normal, state}
  end
  def handle_call(_request, _from, state) do
    {:reply, :ok, state}
  end

  def handle_info({:DOWN, mon_ref, _, _, _}, %State{mon_ref: mon_ref} = state) do
    {:stop, :normal, state}
  end
  def handle_info({sock, :input_ready}, %State{ct: sock} = state) do
    handle_socket_data(sock, &:netlink_codec.nl_ct_dec/1, state)
    {:noreply, state}
  end
  def handle_info({sock, :input_ready}, %State{rt: sock} = state) do
    handle_socket_data(sock, &:netlink_codec.nl_rt_dec/1, state)
    {:noreply, state}
  end
  def handle_info(_info, state) do
    {:noreply, state}
  end

  # private functions

  defp handle_socket_data(sock, decoder, state) do
    :ok = :gen_socket.input_event(sock, true)
    case :gen_socket.recvfrom(sock, 128 * 1024) do
      {:ok, _sender, binary} ->
        binary
        |> decoder.()
        |> Enum.each(&handle_message(&1, state))
      _other ->
        :ok
    end
  end

  defp handle_message(msg, %State{subscriber: {type, pid}}) when elem(msg, 0) == type do
    _ = Process.send(pid, msg, [])
  end
  defp handle_message(_, _state) do
    :ok
  end

  defp socket(family, type, protocol, args) do
    case args[:netns] do
      nil ->
        :gen_socket.socket(family, type, protocol)
      netns ->
        :gen_socket.socketat(netns, family, type, protocol)
    end
  end

  defp bind_with_rcvbufsiz(sock) do
    :ok = :gen_socket.bind(sock, netlink_sockaddr_nl())
    :ok = :gen_socket.input_event(sock, true)
    :ok = :gen_socket.setsockopt(sock, :sol_socket, :sndbuf, 0x8000)
    :ok = rcvbufsiz(sock, 128 * 1024)
  end

  defp netlink_sockaddr_nl,
    do: Netlink.Utils.sockaddr_nl(:netlink, 0, -1)

  defp rcvbufsiz(sock, bufsize) do
    case :gen_socket.setsockopt(sock, :sol_socket, :rcvbufforce, bufsize) do
      :ok -> :ok
      _ -> :gen_socket.setsockopt(sock, :sol_socket, :rcvbuf, bufsize)
    end
  end

  defp setsockopt_ct(ct_netlink) do
    :ok = setsockopt(ct_netlink, :sol_netlink, :netlink_add_membership, :nfnlgrp_conntrack_new)
    :ok = setsockopt(ct_netlink, :sol_netlink, :netlink_add_membership, :nfnlgrp_conntrack_update)
    :ok = setsockopt(ct_netlink, :sol_netlink, :netlink_add_membership, :nfnlgrp_conntrack_destroy)
    :ok = setsockopt(ct_netlink, :sol_netlink, :netlink_add_membership, :nfnlgrp_conntrack_exp_new)
    :ok = setsockopt(ct_netlink, :sol_netlink, :netlink_add_membership, :nfnlgrp_conntrack_exp_update)
    :ok = setsockopt(ct_netlink, :sol_netlink, :netlink_add_membership, :nfnlgrp_conntrack_exp_destroy)
  end

  defp setsockopt_rt(rt_netlink) do
    :ok = setsockopt(rt_netlink, :sol_netlink, :netlink_add_membership, :rtnlgrp_link)
    :ok = setsockopt(rt_netlink, :sol_netlink, :netlink_add_membership, :rtnlgrp_notify)
    :ok = setsockopt(rt_netlink, :sol_netlink, :netlink_add_membership, :rtnlgrp_neigh)
    :ok = setsockopt(rt_netlink, :sol_netlink, :netlink_add_membership, :rtnlgrp_ipv4_ifaddr)
    :ok = setsockopt(rt_netlink, :sol_netlink, :netlink_add_membership, :rtnlgrp_ipv4_route)
    :ok = setsockopt(rt_netlink, :sol_netlink, :netlink_add_membership, :rtnlgrp_ipv6_ifaddr)
    :ok = setsockopt(rt_netlink, :sol_netlink, :netlink_add_membership, :rtnlgrp_ipv6_route)
  end

  defp setsockopt(socket, level, opt_name, value) when is_atom(level),
    do: setsockopt(socket, enc_opt(level), opt_name, value)

  defp setsockopt(socket, level, opt_name, value) when is_atom(opt_name),
    do: setsockopt(socket, level, enc_opt(opt_name), value)

  defp setsockopt(socket, level, opt_name, value) when is_atom(value),
    do: setsockopt(socket, level, opt_name, enc_opt(value))

  defp setsockopt(socket, level, opt_name, value) when is_integer(value),
    do: :gen_socket.setsockopt(socket, level, opt_name, value)
end

