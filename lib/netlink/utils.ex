defmodule Netlink.Utils do
  def mac_hex_to_tuple(mac) do
    <<a1, a2, a3, a4, a5, a6>> = <<(String.to_integer(mac, 16))::48>>
    {a1, a2, a3, a4, a5, a6}
  end

  def if_nametoindex(ifname) do
    res =
      ifname
      |> String.to_charlist
      |> Netlink.Client.if_nametoindex
    case res do
      {:ok, ifindex} -> ifindex
      {:error, _term} = e -> e
    end
  end

  def sockaddr_nl(family, pid, groups) do
    sockaddr_nl({family, pid, groups})
  end

  def sockaddr_nl({family, pid, groups}) when is_atom(family) do
    sockaddr_nl({:gen_socket.family(family), pid, groups})
  end
  def sockaddr_nl({family, pid, groups}) do
    <<family::16-native-integer, 0::16, pid::32-native-integer, groups::32-native-integer>>
  end
  def sockaddr_nl(<< family::16-native-integer, _pad::16, pid::32-native-integer, groups::32-native-integer>>) do
    {:gen_socket.family(family), pid, groups}
  end
end
