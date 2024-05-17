# Structure Network
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
# Implement
```
user> cd Network 
user> sudo python3 network.py

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
