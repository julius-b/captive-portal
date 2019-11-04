# Captive Portal (on Android (root required))
- require users to authenticate (email, pass) / download an app / etc. to join a wifi network.

## How it works
```bash
$ iptables -t nat -A PREROUTING -i $iface -p tcp --dport 80 -j DNAT --to-destination $target_ip:$port
```
> don't DROP connections, just change their destination - clients need to understand that they're being intercepted (e.g. when requesting /gen_204)

## Setup
- to compile the binary for your specific ARM architecture, use 'Termux' (a terminal emulator for android) and install golang (`apt install golang`)
- tested on: LineageOS 16 (OniiChanKernel-R2+)

## Notes
- you don't want to run `iptables -F` on android, the devices usually have about ~50 rules managed by the system :)

## TODO
- actual auth
- dashboard for collected data
- record http requests
- when a authenticated client access the server (/success.txt), redirect to a public webpage

## Improvements
- DNS hijacking (forward udp/tcp 53 to this host, maybe try dnsmasq)
