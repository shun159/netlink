defmodule Netlink.Consts do
  @moduledoc false

  defmacro __using__(_which) do
    quote location: :keep do
      require Record

      import Bitwise

      @gen_netlink_header "gen_netlink/include/netlink.hrl"

      for {name, fields} <- Record.extract_all(from_lib: @gen_netlink_header) do
        Record.defrecord(name, fields)
      end

      ## netlink event sources
      @netlink_route 0
      @netlink_unused 1
      @netlink_usersock 2
      @netlink_firewall 3
      @netlink_inet_diag 4
      @netlink_nflog 5
      @netlink_xfrm 6
      @netlink_selinux 7
      @netlink_iscsi 8
      @netlink_audit 9
      @netlink_fib_lookup 10
      @netlink_connector 11
      @netlink_netfilter 12
      @netlink_ip6_fw 13
      @netlink_dnrtmsg 14
      @netlink_kobject_uevent 15
      @netlink_generic 16
      @netlink_scsitransport 18
      @netlink_ecryptfs 19

      @nud_incomplete 0x01
      @nud_reachable  0x02
      @nud_stale      0x04
      @nud_delay      0x08
      @nud_probe      0x10
      @nud_failed     0x20
      ## dummy states
      @nud_noarp      0x40
      @nud_permanent  0x80
      @nud_none       0x00

      @nf_drop   0
      @nf_accept 1
      @nf_stolen 2
      @nf_queue  3
      @nf_repeat 4
      @nf_stop   5

      ## flags values */

      @nlm_f_request           1       ## it is request message.
      @nlm_f_multi             2       ## multipart message terminated by nlmsg_done
      @nlm_f_ack               4       ## reply with ack with zero or error code
      @nlm_f_echo              8       ## echo this request
      @nlm_f_dump_intr         16      ## dump was inconsistent due to sequence change

      ## modifiers to get request
      @nlm_f_root      0x100   ## specify tree root
      @nlm_f_match     0x200   ## return all matching
      @nlm_f_atomic    0x400   ## atomic get
      @nlm_f_dump      (@nlm_f_root ||| @nlm_f_match)

      ## modifiers to new request
      @nlm_f_replace   0x100   ## override existing
      @nlm_f_excl      0x200   ## do not touch if it exists
      @nlm_f_create    0x400   ## create if it does not exist
      @nlm_f_append    0x800   ## add to end of list


      ## netlink info
      @nlmsg_min_type 0x10

      @netlink_add_membership 1
      @netlink_drop_membership 2
      @netlink_pktinfo 3
      @netlink_broadcast_error 4
      @netlink_no_enobufs 5

      @sol_netlink 270

      @nfnlgrp_none 0
      @nfnlgrp_conntrack_new 1
      @nfnlgrp_conntrack_update 2
      @nfnlgrp_conntrack_destroy 3
      @nfnlgrp_conntrack_exp_new 4
      @nfnlgrp_conntrack_exp_update 5
      @nfnlgrp_conntrack_exp_destroy 6

      @nfnl_msg_batch_begin @nlmsg_min_type
      @nfnl_msg_batch_end   @nfnl_msg_batch_begin + 1

      @rtnlgrp_none 0
      @rtnlgrp_link 1
      @rtnlgrp_notify 2
      @rtnlgrp_neigh 3
      @rtnlgrp_tc 4
      @rtnlgrp_ipv4_ifaddr 4
      @rtnlgrp_ipv4_mroute 5
      @rtnlgrp_ipv4_route 6
      @rtnlgrp_ipv4_rule 7
      @rtnlgrp_ipv6_ifaddr 8
      @rtnlgrp_ipv6_mroute 9
      @rtnlgrp_ipv6_route 10
      @rtnlgrp_ipv6_ifinfo 11
      @rtnlgrp_decnet_ifaddr 12
      @rtnlgrp_nop2 13
      @rtnlgrp_decnet_route 14
      @rtnlgrp_decnet_rule 15
      @rtnlgrp_nop4 16
      @rtnlgrp_ipv6_prefix 17
      @rtnlgrp_ipv6_rule 18
      @rtnlgrp_nd_useropt 19
      @rtnlgrp_phonet_ifaddr 20
      @rtnlgrp_phonet_route 21

      @nlmsg_noop 1
      @nlmsg_error 2
      @nlmsg_done 3
      @nlmsg_overrun 4

      @rtm_newlink 16
      @rtm_dellink 17
      @rtm_getlink 18
      @rtm_setlink 19
      @rtm_newaddr 20
      @rtm_deladdr 21
      @rtm_getaddr 22
      @rtm_newroute 24
      @rtm_delroute 25
      @rtm_getroute 26
      @rtm_newneigh 28
      @rtm_delneigh 29
      @rtm_getneigh 30
      @rtm_newrule 32
      @rtm_delrule 33
      @rtm_getrule 34
      @rtm_newqdisc 36
      @rtm_delqdisc 37
      @rtm_getqdisc 38
      @rtm_newtclass 40
      @rtm_deltclass 41
      @rtm_gettclass 42
      @rtm_newtfilter 44
      @rtm_deltfilter 45
      @rtm_gettfilter 46
      @rtm_newaction 48
      @rtm_delaction 49
      @rtm_getaction 50
      @rtm_newprefix 52
      @rtm_getmulticast 58
      @rtm_getanycast 62
      @rtm_newneightbl 64
      @rtm_getneightbl 66
      @rtm_setneightbl 67
      @rtm_newnduseropt 68
      @rtm_newaddrlabel 72
      @rtm_deladdrlabel 73
      @rtm_getaddrlabel 74
      @rtm_getdcb 78
      @rtm_setdcb 79
      @rtm_newnetconf 80
      @rtm_getnetconf 82
      @rtm_newmdb 84
      @rtm_delmdb 85
      @rtm_getmdb 86
      @rtm_newnsid 88
      @rtm_delnsid 89
      @rtm_getnsid 90
      @rtm_newstats 92
      @rtm_getstats 94

      @ipctnl_msg_ct_new 0
      @ipctnl_msg_ct_get 1
      @ipctnl_msg_ct_delete 2
      @ipctnl_msg_ct_get_ctrzero 3

      @ipctnl_msg_exp_new 0
      @ipctnl_msg_exp_get 1
      @ipctnl_msg_exp_delete 2

      @nfqnl_msg_packet 0              ## packet from kernel to userspace
      @nfqnl_msg_verdict 1             ## verdict from userspace to kernel
      @nfqnl_msg_config 2              ## connect to a particular queue
      @nfqnl_msg_verdict_batch 3       ## batchv from userspace to kernel

      @nfqa_cfg_unspec 0
      @nfqa_cfg_cmd 1                  ## nfqnl_msg_config_cmd
      @nfqa_cfg_params 2               ## nfqnl_msg_config_params
      @nfqa_cfg_queue_maxlen 3         ## u_int32_t

      @nfqnl_cfg_cmd_none 0
      @nfqnl_cfg_cmd_bind 1
      @nfqnl_cfg_cmd_unbind 2
      @nfqnl_cfg_cmd_pf_bind 3
      @nfqnl_cfg_cmd_pf_unbind 4

      defp enc_opt(:netlink_route), do:                 @netlink_route
      defp enc_opt(:netlink_unused), do:                @netlink_unused
      defp enc_opt(:netlink_usersock), do:              @netlink_usersock
      defp enc_opt(:netlink_firewall), do:              @netlink_firewall
      defp enc_opt(:netlink_inet_diag), do:             @netlink_inet_diag
      defp enc_opt(:netlink_nflog), do:                 @netlink_nflog
      defp enc_opt(:netlink_xfrm), do:                  @netlink_xfrm
      defp enc_opt(:netlink_selinux), do:               @netlink_selinux
      defp enc_opt(:netlink_iscsi), do:                 @netlink_iscsi
      defp enc_opt(:netlink_audit), do:                 @netlink_audit
      defp enc_opt(:netlink_fib_lookup), do:            @netlink_fib_lookup
      defp enc_opt(:netlink_connector), do:             @netlink_connector
      defp enc_opt(:netlink_netfilter), do:             @netlink_netfilter
      defp enc_opt(:netlink_ip6_fw), do:                @netlink_ip6_fw
      defp enc_opt(:netlink_dnrtmsg), do:               @netlink_dnrtmsg
      defp enc_opt(:netlink_kobject_uevent), do:        @netlink_kobject_uevent
      defp enc_opt(:netlink_generic), do:               @netlink_generic
      defp enc_opt(:netlink_scsitransport), do:         @netlink_scsitransport
      defp enc_opt(:netlink_ecryptfs), do:              @netlink_ecryptfs
      defp enc_opt(:netlink_add_membership), do:        @netlink_add_membership
      defp enc_opt(:netlink_drop_membership), do:       @netlink_drop_membership
      defp enc_opt(:netlink_pktinfo), do:               @netlink_pktinfo
      defp enc_opt(:netlink_broadcast_error), do:       @netlink_broadcast_error
      defp enc_opt(:netlink_no_enobufs), do:            @netlink_no_enobufs
      defp enc_opt(:sol_netlink), do:                   @sol_netlink
      defp enc_opt(:nfnlgrp_none), do:                  @nfnlgrp_none
      defp enc_opt(:nfnlgrp_conntrack_new), do:         @nfnlgrp_conntrack_new
      defp enc_opt(:nfnlgrp_conntrack_update), do:      @nfnlgrp_conntrack_update
      defp enc_opt(:nfnlgrp_conntrack_destroy), do:     @nfnlgrp_conntrack_destroy
      defp enc_opt(:nfnlgrp_conntrack_exp_new), do:     @nfnlgrp_conntrack_exp_new
      defp enc_opt(:nfnlgrp_conntrack_exp_update), do:  @nfnlgrp_conntrack_exp_update
      defp enc_opt(:nfnlgrp_conntrack_exp_destroy), do: @nfnlgrp_conntrack_exp_destroy
      defp enc_opt(:rtnlgrp_none), do:                  @rtnlgrp_none
      defp enc_opt(:rtnlgrp_link), do:                  @rtnlgrp_link
      defp enc_opt(:rtnlgrp_notify), do:                @rtnlgrp_notify
      defp enc_opt(:rtnlgrp_neigh), do:                 @rtnlgrp_neigh
      defp enc_opt(:rtnlgrp_tc), do:                    @rtnlgrp_tc
      defp enc_opt(:rtnlgrp_ipv4_ifaddr), do:           @rtnlgrp_ipv4_ifaddr
      defp enc_opt(:rtnlgrp_ipv4_mroute), do:           @rtnlgrp_ipv4_mroute
      defp enc_opt(:rtnlgrp_ipv4_route), do:            @rtnlgrp_ipv4_route
      defp enc_opt(:rtnlgrp_ipv4_rule), do:             @rtnlgrp_ipv4_rule
      defp enc_opt(:rtnlgrp_ipv6_ifaddr), do:           @rtnlgrp_ipv6_ifaddr
      defp enc_opt(:rtnlgrp_ipv6_mroute), do:           @rtnlgrp_ipv6_mroute
      defp enc_opt(:rtnlgrp_ipv6_route), do:            @rtnlgrp_ipv6_route
      defp enc_opt(:rtnlgrp_ipv6_ifinfo), do:           @rtnlgrp_ipv6_ifinfo
      defp enc_opt(:rtnlgrp_decnet_ifaddr), do:         @rtnlgrp_decnet_ifaddr
      defp enc_opt(:rtnlgrp_nop2), do:                  @rtnlgrp_nop2
      defp enc_opt(:rtnlgrp_decnet_route), do:          @rtnlgrp_decnet_route
      defp enc_opt(:rtnlgrp_decnet_rule), do:           @rtnlgrp_decnet_rule
      defp enc_opt(:rtnlgrp_nop4), do:                  @rtnlgrp_nop4
      defp enc_opt(:rtnlgrp_ipv6_prefix), do:           @rtnlgrp_ipv6_prefix
      defp enc_opt(:rtnlgrp_ipv6_rule), do:             @rtnlgrp_ipv6_rule
      defp enc_opt(:rtnlgrp_nd_useropt), do:            @rtnlgrp_nd_useropt
      defp enc_opt(:rtnlgrp_phonet_ifaddr), do:         @rtnlgrp_phonet_ifaddr
      defp enc_opt(:rtnlgrp_phonet_route), do:          @rtnlgrp_phonet_route
    end
  end
end
