#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6633)

     # Add physical interface
    info( 'Defining physical interface\n' )
    intfName = 'enp0s9'

    info( '*** Add switches\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
    
    info( '*** Add hosts\n')
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', defaultRoute='via 10.0.0.254')
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2', defaultRoute='via 10.0.0.254')
    h3 = net.addHost('h3', cls=Host, ip='10.0.0.3', defaultRoute='via 10.0.0.254')
    r1 = net.addHost('r1', cls=Node, ip='10.0.0.254')

    
    info( '*** Add links\n')
    net.addLink(s1, r1)
    net.addLink(s1, h1)
    net.addLink(s1, h2)
    net.addLink(s1, h3)
    
    info( 'Adding hardware interface', intfName, 'to router', r1.name, '\n' )
    _intf = Intf( intfName, node=r1, ip='192.168.56.254/24')

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s1').start([c0])

    info( '*** Post configure switches and hosts\n')
    r1.cmd('sysctl -w net.ipv4.ip_forward=1')
    h1.cmdPrint('/usr/sbin/sshd')
    h2.cmdPrint('/usr/sbin/sshd')
    h3.cmdPrint('/usr/sbin/sshd')
    
    net.startTerms()
    
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

