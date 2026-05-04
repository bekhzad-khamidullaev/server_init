#!/bin/zsh
set -euo pipefail
set +H

HOST="192.168.88.254"
PORT="2222"
USER="admin"
PASS='Bek@1427477'

run_cmd() {
  local CMD="$1"
  HOST="$HOST" PORT="$PORT" USER="$USER" PASS="$PASS" CMD="$CMD" expect <<'EOT'
set timeout 50
log_user 0
set host $env(HOST)
set port $env(PORT)
set user $env(USER)
set pass $env(PASS)
set cmd  $env(CMD)
spawn ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $port $user@$host $cmd
expect "*assword:*" { send "$pass\r" }
expect eof
EOT
  echo "OK: $CMD"
}

run_cmd '/export file=pre_fw_hardening_no_ip_limit_20260319'
run_cmd '/system backup save name=pre_fw_hardening_no_ip_limit_20260319'
run_cmd ':if ([:len [/interface list find where name="WAN_ALL"]] = 0) do={ /interface list add name=WAN_ALL }'
run_cmd ':if ([:len [/interface list member find where list="WAN_ALL" and interface="east_inet_br"]] = 0) do={ /interface list member add list=WAN_ALL interface=east_inet_br }'
run_cmd ':if ([:len [/interface list member find where list="WAN_ALL" and interface="ut_inet_br1"]] = 0) do={ /interface list member add list=WAN_ALL interface=ut_inet_br1 }'
run_cmd ':if ([:len [/interface list member find where list="WAN_ALL" and interface="ut_inet_br2"]] = 0) do={ /interface list member add list=WAN_ALL interface=ut_inet_br2 }'
run_cmd ':if ([:len [/interface list member find where list="WAN_ALL" and interface="ut_inet_br3"]] = 0) do={ /interface list member add list=WAN_ALL interface=ut_inet_br3 }'
run_cmd '/ip settings set tcp-syncookies=yes accept-source-route=no accept-redirects=no secure-redirects=no send-redirects=no rp-filter=loose'
run_cmd ':if ([:len [/ip firewall filter find where comment="INPUT established"]] = 0) do={ /ip firewall filter add chain=input action=accept connection-state=established,related,untracked place-before=0 comment="INPUT established" }'
run_cmd ':if ([:len [/ip firewall filter find where comment="INPUT invalid"]] = 0) do={ /ip firewall filter add chain=input action=drop connection-state=invalid place-before=0 comment="INPUT invalid" }'
run_cmd ':if ([:len [/ip firewall filter find where comment="INPUT allow SSH/Winbox WAN"]] = 0) do={ /ip firewall filter add chain=input action=accept protocol=tcp dst-port=2222,8291 in-interface-list=WAN_ALL place-before=0 comment="INPUT allow SSH/Winbox WAN" }'
run_cmd ':if ([:len [/ip firewall filter find where comment="INPUT allow API-SSL WAN"]] = 0) do={ /ip firewall filter add chain=input action=accept protocol=tcp dst-port=8729 in-interface-list=WAN_ALL place-before=0 comment="INPUT allow API-SSL WAN" }'
run_cmd ':if ([:len [/ip firewall filter find where comment="INPUT drop blacklisted mgmt"]] = 0) do={ /ip firewall filter add chain=input action=drop src-address-list=MGMT_BLACKLIST place-before=0 comment="INPUT drop blacklisted mgmt" }'
run_cmd ':if ([:len [/ip firewall filter find where comment="MGMT stage3->blacklist"]] = 0) do={ /ip firewall filter add chain=input action=add-src-to-address-list protocol=tcp dst-port=2222,8291 in-interface-list=WAN_ALL connection-state=new src-address-list=MGMT_STAGE3 address-list=MGMT_BLACKLIST address-list-timeout=1d place-before=0 comment="MGMT stage3->blacklist" }'
run_cmd ':if ([:len [/ip firewall filter find where comment="MGMT stage2->3"]] = 0) do={ /ip firewall filter add chain=input action=add-src-to-address-list protocol=tcp dst-port=2222,8291 in-interface-list=WAN_ALL connection-state=new src-address-list=MGMT_STAGE2 address-list=MGMT_STAGE3 address-list-timeout=1m place-before=0 comment="MGMT stage2->3" }'
run_cmd ':if ([:len [/ip firewall filter find where comment="MGMT stage1->2"]] = 0) do={ /ip firewall filter add chain=input action=add-src-to-address-list protocol=tcp dst-port=2222,8291 in-interface-list=WAN_ALL connection-state=new src-address-list=MGMT_STAGE1 address-list=MGMT_STAGE2 address-list-timeout=1m place-before=0 comment="MGMT stage1->2" }'
run_cmd ':if ([:len [/ip firewall filter find where comment="MGMT new->stage1"]] = 0) do={ /ip firewall filter add chain=input action=add-src-to-address-list protocol=tcp dst-port=2222,8291 in-interface-list=WAN_ALL connection-state=new address-list=MGMT_STAGE1 address-list-timeout=1m place-before=0 comment="MGMT new->stage1" }'
run_cmd ':if ([:len [/ip firewall filter find where comment="INPUT IKE"]] = 0) do={ /ip firewall filter add chain=input action=accept protocol=udp dst-port=500,4500,8805 place-before=0 comment="INPUT IKE" }'
run_cmd ':if ([:len [/ip firewall filter find where comment="INPUT ESP"]] = 0) do={ /ip firewall filter add chain=input action=accept protocol=ipsec-esp place-before=0 comment="INPUT ESP" }'
run_cmd ':if ([:len [/ip firewall filter find where comment="INPUT AH"]] = 0) do={ /ip firewall filter add chain=input action=accept protocol=ipsec-ah place-before=0 comment="INPUT AH" }'
run_cmd ':if ([:len [/ip firewall filter find where comment="INPUT drop rest WAN"]] = 0) do={ /ip firewall filter add chain=input action=drop in-interface-list=WAN_ALL place-before=0 comment="INPUT drop rest WAN" }'
run_cmd ':if ([:len [/ip firewall filter find where comment="FWD established"]] = 0) do={ /ip firewall filter add chain=forward action=accept connection-state=established,related,untracked place-before=0 comment="FWD established" }'
run_cmd ':if ([:len [/ip firewall filter find where comment="FWD invalid"]] = 0) do={ /ip firewall filter add chain=forward action=drop connection-state=invalid place-before=0 comment="FWD invalid" }'
run_cmd ':if ([:len [/ip firewall filter find where comment="FWD IPsec in"]] = 0) do={ /ip firewall filter add chain=forward action=accept ipsec-policy=in,ipsec place-before=0 comment="FWD IPsec in" }'
run_cmd ':if ([:len [/ip firewall filter find where comment="FWD IPsec out"]] = 0) do={ /ip firewall filter add chain=forward action=accept ipsec-policy=out,ipsec place-before=0 comment="FWD IPsec out" }'
run_cmd ':if ([:len [/ip firewall filter find where comment="FWD drop unsolicited WAN"]] = 0) do={ /ip firewall filter add chain=forward action=drop in-interface-list=WAN_ALL connection-state=new connection-nat-state=!dstnat place-before=0 comment="FWD drop unsolicited WAN" }'
run_cmd ':if ([:len [/ip firewall raw find where comment="IPS-drop_in_bad_traffic"]] > 0) do={ /ip firewall raw enable [find where comment="IPS-drop_in_bad_traffic"] }'
run_cmd ':if ([:len [/ip firewall raw find where comment="IPS-drop_out_bad_traffic"]] > 0) do={ /ip firewall raw enable [find where comment="IPS-drop_out_bad_traffic"] }'
run_cmd ':if ([:len [/ip firewall address-list find where list="trusted-ips" and address="0.0.0.0"]] > 0) do={ /ip firewall address-list remove [find where list="trusted-ips" and address="0.0.0.0"] }'
run_cmd '/ip settings print'
run_cmd '/interface list print where name="WAN_ALL"'
run_cmd '/interface list member print where list="WAN_ALL"'
run_cmd '/ip firewall filter print where comment~"INPUT|FWD|MGMT"'
run_cmd '/ip firewall raw print detail where comment~"IPS-drop"'
run_cmd '/ip firewall address-list print where list=trusted-ips and address=0.0.0.0'

echo "DONE"
