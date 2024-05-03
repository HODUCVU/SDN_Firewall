SDN_Firewall
============
## My Topic
* [Introduction topic](/Documents/IntroductionTopicSDN.pdf)

* [Introduction from paper](/Documents/2015-IDP-OpenFlow-Firewall.pdf)
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
