"""
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
"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

# Ryu controller
ryu_ip = '127.0.0.1'
ryu_port = 6653

# Define remote RYU Controller
print ('Ryu IP Address: {}'.format( ryu_ip))
print ('Ryu Port No: {}'.format(ryu_port))

def network():
    net = Mininet(topo=None, build=False)
    # Add controller
    info("Adding controller...\n")
    net.addController('c0', controller=RemoteController, ip=ryu_ip,port=ryu_port)

    # Add host
    info("Adding hosts...\n")
    h1, h2, h3, h4, h5 = [net.addHost(h) for h in ('h1', 'h2', 'h3', 'h4', 'h5')]
    h6, h7, h8, h9, h10 = [net.addHost(h) for h in ('h6', 'h7', 'h8', 'h9', 'h10')]
    h11, h12, h13, h14, h15 = [net.addHost(h) for h in ('h11', 'h12', 'h13', 'h14', 'h15')]
    # Add switches
    info("Adding switches...\n")
    s1, s2, s3 = [net.addSwitch(s) for s in ('s1', 's2', 's3')]
    # Add links
    info("Adding switch links...\n")
    for sa, sb in [(s1, s2), (s2, s3)]:
        net.addLink(sa, sb)
    for h, s in [(h1, s1), (h2, s1), (h3, s1), (h4, s1), (h5, s1)]:
        net.addLink(h, s)
    for h, s in [(h6, s2), (h7, s2), (h8, s2), (h9, s2), (h10, s2)]:
        net.addLink(h, s)
    for h, s in [(h11, s3), (h12, s3), (h13, s3), (h14, s3), (h15, s3)]:
        net.addLink(h, s)

    info("*** Starting network ***\n")
    net.start()
    info("*** Running CLI ***\n")
    CLI(net)

    info("*** Stopping network ***\n")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    network()

exit(0)
