# Report's Group 9.
## Member
1. Ho Duc Vu - 20KTMT2.
2. Huynh Vu Dinh Phuoc - 20KTMT1.
3. Nguyen Minh Phuong - 20KTMT1.
## Important files 
```
├── Documents
│   ├── Report_SDN-Firewall_And_Application_Control_Network.pdf
│   ├── Slide-Group9.pptx
├── Firewall
│   ├── connection_tracking.py
│   ├── construct_flow.py
│   ├── dataset
│   │   ├── firewall-drop.db
│   ├── FirewallDrop.py
│   ├── flow_addition.py
│   ├── flowtracker.py
│   ├── packet_out.py
│   ├── ParseFirewallFromDB.py
│   ├── reset_flow_table.py
│   ├── SQL
│   │   ├── firewall.csv
│   │   ├── initDB.py
│   └── switch_information.py
├── Network
│   └── network.py
├── Application
│   └── ... 
```
## Links
1. [Slide](https://github.com/HODUCVU/SDN_Firewall/blob/Report/Documents/Slide-Group9.pptx)
2. [Report version pdf]() 
# SDN_Firewall
## My Topic
* Tutorial and result for this project: [SDN Firewall and Application control Network.](https://github.com/HODUCVU/SDN_Firewall/blob/main/Documents/SDN-Firewall_And_Application_Control_Network.pdf)
<!--* [Introduction topic](https://github.com/HODUCVU/SDN_Firewall/blob/main/Documents/Project's_Introduction.pdf) -->
* [Introduction from paper](/Documents/2015-IDP-OpenFlow-Firewall.pdf)
## Important files 
```
.
├── Documents
│   ├── SDN-Firewall_And_Application_Control_Network.pdf *********
│   ├── 2015-IDP-OpenFlow-Firewall.pdf
│   ├── Project's_Introduction.pdf
│   ├── README.md
├── Firewall
│   ├── connection_tracking.py
│   ├── construct_flow.py
│   ├── customFirewallStateful.py
│   ├── dataset
│   │   ├── firewall-drop.db
│   │   └── firewall-vTest.db
│   ├── FirewallDrop.py ***************
│   ├── flow_addition.py
│   ├── packet_out.py
│   ├── ParseFirewallFromDB.py 
│   ├── parse_firewall_rules.py
│   ├── reset_flow_table.py
│   ├── SQL
│   │   ├── firewallDB.txt
│   │   ├── firewallDrop.csv
│   │   ├── initDB.py
│   └── switch_information.py
├── Network
│   └── network.py
├── application
├── README.md
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

## Run check for Firewall
* Step 1: Create network 
```
> cd Network 
> sudo python3 network.py
```
<!-- ``` -->
<!-- > sudo mn --topo single,4 --mac --controller remote,ip=127.0.0.1 -i 10.0.0.0/24 --switch ovsk -->
<!-- ``` -->
* Step 2: Open terminal for devices 
```
mininet> xterm c0 h1 h2 h3 <...>
```
* Step 3: Check
  * Controller
  ```
  c0> cd Firewall
  c0> ryu-manager FirewallDrop.py
  ```
  * Ping with ICMP protocol
  ```
  h1> ping -c2 10.0.0.2 
  // Drop
  h2> ping -c1 10.0.0.1 
  // connect (don't have in table drop)
  //and ...
  // ping to other ip to check connect
  ```
  * Ping with TCP protocol
  ```
  h1 (SYN)> hping3 -c 10 -k -s 1000 -p 8080 -S 10.0.0.2 
  h1 (SYN_ASK)> hping3 -c 10 -k -s 1000 -p 8080 -SA 10.0.0.2 
  //-> DROP 
  h2 (SYN)> hping3 -c 10 -k -s 8080 -p 1000 -S 10.0.0.1 
  h2 (SYN_ASK)> hping3 -c 10 -k -s 8080 -p 1000 -SA 10.0.0.1 
  //-> DROP
  //and ...
  // ping to other port to check connect
  ```
  * Ping with UDP protocol 
  ```
  h1> hping3 --udp -c 10 -k -s 1000 -p 8080 10.0.0.2
  h2> hping3 --udp -c 10 -k -s 8080 -p 1000 10.0.0.1
  //and ...
  ```
<!-- ## Works -->
<!-- 1. Check query database from rules. -- Done -->
<!-- 2. Covert database from 'ALLOW' to 'DROP'. -- Done -->
<!-- 3. Create rule check times send packet from source IP Address. -- Done -->
<!-- 4. Run on project' network (3 switch). -- Done -->

# Demo on Application
Video demo is pushed on [Youtube](https://www.youtube.com/watch?v=Y4_bdANML4c&fbclid=IwAR0CCl0YLMpUoshtkUvCrPExZ2ZvN3odxbjxDokLjhsl_V-wVNAzPE99YIA)
