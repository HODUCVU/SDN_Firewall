# Problem
* Why choice this topic.
* Advantages and disadvantages of traditional firewall and SDN firewall.
# Solve
* How does Firewall meet the advantages of SDN and how it solve disadvantage.
* What functions does Firewall have and compare for traditional firewall.
* Find out all the rules for the Firewall and deploy those instances.
* Use protocols :IP -> IPv4/IPv6, TCP/IP, UDP, ICMP
* Why block that host? What package will block and what doesn't block?
* Check for irregularities in flows. Different s\_ips have the same dst\_ip
* Check payload, if packages don't payload then this package is potential package attack to host/switch.
* There is no need to block all packets from a host, but to optimize it, block only files that are potentially malicious, or block only when the file has certain properties.
* Run real-time
# Works
1. Fix code -> Done
2. Find out all the rules for the Firewall and deploy those instances.
  - Why block that host? What packets will block and what doesn't block?
  - Check for irregularities in flows. Example: Diffrent s_ips have the same dst_ip, or One s_ips send packets to overnumber host.
  - Check payload, if packets don't have payload then this packets is potential packets attack to host/switch.
  - No need to block all packets from a host, justt block only files that are potential malicious, or block only when the file has certain properties.
3. Run real-time:
  - Connect database: sql lite
  - Connect api
# Result
# Conclusion
* Irrelevant: tracking package's payload use 'deep package inspection' and use AI for it

