# Firewall - run on python3.8
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

# Run check for Firewall
* Step 1: Create network 
```
> cd Network 
> sudo python3 network.py
```
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
  * Ping flood -> DROP
  ```
  // ICMP
  h5> ping -f 10.0.0.10
  // TCP
  h2> hping3 -c 10 -k -s 8080 -p 1000 10.0.0.8 --flood
  // UDP
  h2> hping3 -2 -c 10 -k -s 8080 -p 8080 10.0.0.7 --flood
  ```
