SDN_Firewall
============
## My Topic
* [Introduction topic](/Documents/IntroductionTopicSDN.pdf)
* [Introduction from paper](/Documents/2015-IDP-OpenFlow-Firewall.pdf)
## Structure repository
```
.
├── Documents
│   ├── 2015-IDP-OpenFlow-Firewall.pdf
│   ├── IntroductionTopicSDN.pdf
│   └── README.md
├── Firewall
│   ├── connection_tracking.py
│   ├── construct_flow.py
│   ├── customFirewallStateful.py
│   ├── firewall.txt
│   ├── flow_addition.py
│   ├── packet_out.py
│   ├── parse_firewall_rules.py
│   ├── __pycache__
│   │   ├── connection_tracking.cpython-38.pyc
│   │   ├── construct_flow.cpython-38.pyc
│   │   ├── customFirewallStateful.cpython-38.pyc
│   │   ├── flow_addition.cpython-38.pyc
│   │   ├── packet_out.cpython-38.pyc
│   │   ├── parse_firewall_rules.cpython-38.pyc
│   │   ├── reset_flow_table.cpython-38.pyc
│   │   └── switch_information.cpython-38.pyc
│   ├── reset_flow_table.py
│   ├── switch_information.py
│   └── testRealTime
│       ├── firewall.csv
│       ├── firewall.db
│       ├── firewallDB.txt
│       ├── initDB.py
│       └── parse_firewall_rules_db.py
├── Network
│   └── network.py
├── README.md
└── src
    ├── connection_tracking.py
    ├── construct_flow.py
    ├── firewall_stateful.txt
    ├── firewall_stateless.txt
    ├── firewall.txt
    ├── flow_addition.py
    ├── inefficient_stateful_firewall.py
    ├── inefficient_stateless_firewall.py
    ├── packet_out.py
    ├── parse_firewall_rules.py
    ├── __pycache__
    │   ├── connection_tracking.cpython-38.pyc
    │   ├── construct_flow.cpython-38.pyc
    │   ├── flow_addition.cpython-38.pyc
    │   ├── inefficient_stateful_firewall.cpython-38.pyc
    │   ├── packet_out.cpython-38.pyc
    │   ├── parse_firewall_rules.cpython-38.pyc
    │   ├── reset_flow_table.cpython-38.pyc
    │   └── switch_information.cpython-38.pyc
    ├── reset_flow_table.py
    ├── secure_stateful_firewall.py
    ├── secure_stateless_firewall.py
    └── switch_information.py

7 directories, 49 files
```
## Firewall - run on python3.8
### Test Firewall
* Step 1: Create network 
```
> sudo mn --topo single,4 --mac --controller remote,ip=127.0.0.1 -i 10.0.0.0/24 --switch ovsk
```
* Step 2: Open terminal for devices 
```
mininet> xterm c0 s1 h1 h2
```
* Step 3: Test
  * Controller
  ```
  c0> cd Firewall
  c0> ryu-manager customFirwallStateful.py
  ```
  * Switch 
  ```
  s1> set Bridge s1
  ```
  * Hosts
  ```
  h1> ping -c2 10.0.0.2 
  // connect establish
  h2> ping -c1 10.0.0.1 
  //block ping
  ```
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
