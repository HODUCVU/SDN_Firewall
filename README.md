SDN_Firewall
============
## My Topic
* [Introduction topic](https://github.com/HODUCVU/SDN_Firewall/blob/main/Documents/Project's_Introduction.pdf)
* [Introduction from paper](/Documents/2015-IDP-OpenFlow-Firewall.pdf)
## Structure repository

### Network 
* Structure Network
```
Three directly connected switches plus a host attached to each switch 
with a remote RYU SDN Controller (c0):
                _ _ _ _ _ c0_ _ _ _ _ _
              /           |             \
             /            |              \
            /             |               \
           /              |                \
          /               |                 \
     ----s1--------------s2-----------------s3------
    / /  |  \ \     / /  |  \ \      /   /  |   \   \
   h1 h2 h3 h4 h5  h6 h7 h8 h9 h10  h11 h12 h13 h14 h15
```
* Implement
```
> cd Network 
> sudo python3 network.py

mininet> net
h1 h1-eth0:s1-eth2
h2 h2-eth0:s1-eth3
h3 h3-eth0:s1-eth4
h4 h4-eth0:s1-eth5
h5 h5-eth0:s1-eth6
h6 h6-eth0:s2-eth3
h7 h7-eth0:s2-eth4
h8 h8-eth0:s2-eth5
h9 h9-eth0:s2-eth6
h10 h10-eth0:s2-eth7
h11 h11-eth0:s3-eth2
h12 h12-eth0:s3-eth3
h13 h13-eth0:s3-eth4
h14 h14-eth0:s3-eth5
h15 h15-eth0:s3-eth6
s1 lo:  s1-eth1:s2-eth1 s1-eth2:h1-eth0 s1-eth3:h2-eth0 s1-eth4:h3-eth0 s1-eth5:h4-eth0 s1-eth6:h5-eth0
s2 lo:  s2-eth1:s1-eth1 s2-eth2:s3-eth1 s2-eth3:h6-eth0 s2-eth4:h7-eth0 s2-eth5:h8-eth0 s2-eth6:h9-eth0 s2-eth7:h10-eth0
s3 lo:  s3-eth1:s2-eth2 s3-eth2:h11-eth0 s3-eth3:h12-eth0 s3-eth4:h13-eth0 s3-eth5:h14-eth0 s3-eth6:h15-eth0
c0
```
## Firewall - run on python3.8
### Database
* Step 1: Create database
```
SDN_Firewall> cd Firewall/SQL
// Create database - it on Firewall/dataset/firewall-vTest.db already
SQL> python3 initDB.py
```
* Step 2: Check database  
```
Firewall> python3 ParseFirewallFromDB.py
```

### Run check for Firewall
* Step 1: Create network 
```
> sudo mn --topo single,4 --mac --controller remote,ip=127.0.0.1 -i 10.0.0.0/24 --switch ovsk
```
* Step 2: Open terminal for devices 
```
mininet> xterm c0 h1 h2
```
* Step 3: Check
  * Controller
  ```
  c0> cd Firewall
  c0> ryu-manager customFirwallStateful.py
  ```
  * Switch 
  ```
  s1> set Bridge s1
  ```
  * Ping with ICMP protocol
  ```
  h1> ping -c2 10.0.0.2 
  // connect establish
  h2> ping -c1 10.0.0.1 
  //block ping
  and ...
  ```
  * Ping with TCP protocol
  ```
  h1> hping3 -c 1 -s 1000 -p 8080 10.0.0.2 
  //-> BLOCK 
  h2> hping3 -c 1 -s 8080 -p 1000 10.0.0.1 
  //-> SYN ALLOWED
  and ...
  ```
  * Ping with UDP protocol 
  ```
  h1> hping3 --udp -c 10 -s 1000 -p 8080 -S 10.0.0.2
  h2> hping3 --udp -c 10 -s 8080 -p 1000 -S 10.0.0.1
  and ...
  ```
## Works
1. Check query database from rules.
2. Covert database from 'ALLOW' to 'DROP'.
3. Create rule check times send packet from source IP Address.
4. Run on project' network (3 switch).
