defmodule Netlink.Mixfile do
  use Mix.Project

  def project do
    [
      app: :netlink,
      version: "0.1.0",
      elixir: "~> 1.5",
      compilers: Mix.compilers,
      start_permanent: Mix.env == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :gen_netlink, :gen_socket]
    ]
  end

  defp deps do
    [
      {:gen_netlink, github: "shun159/gen_netlink", manager: :rebar3},
      {:gen_socket, github: "travelping/gen_socket"},
      {:procket, github: "msantos/procket", branch: "master", override: true},
      {:lager, github: "basho/lager", tag: "3.2.1", manger: :rebar3, override: true}
    ]
  end
end
