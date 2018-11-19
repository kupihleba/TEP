# VPN-Proxy-Firewall

Program that behaves like a firewall, that encapsulates IP packets into encrypted TCP chunks and transfers them to the remote host.


#### **Libraries required:**
* [Tins][Tins] (High-level library for parsing & sending packets) 
* libmnl-dev (Netlink library) _# apt install libmnl-dev_
* [netfilter_queue][netfilter_queue] (API for packets, that have been queued by the kernel packet filter)

Remember running `# ldconfig` after installation of libraries.


#### **Example of firewall usage:**

`# iptables -A INPUT -s 192.168.1.0/24 -j NFQUEUE --queue-num 0`


[Tins]: https://libtins.github.io

[netfilter_queue]: https://netfilter.org/projects/libnetfilter_queue/index.html