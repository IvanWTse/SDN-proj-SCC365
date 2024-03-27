from mininet.topo import Topo
from mininet.link import TCLink


class MyTopo(Topo):
    def build(self):
        switches = []
        hosts = []

        # Add three switches
        for i in range(1, 4):
            switches.append(self.addSwitch('s' + str(i)))

        # Add seven hosts
        for i in range(1, 8):
            tempHost = self.addHost('h' + str(i))
            hosts.append(tempHost)
            # Link first three hosts to s1
            if i < 4:
                self.addLink(switches[0], tempHost)
            # Link the fourth host to s2
            elif i == 4:
                self.addLink(switches[1], tempHost)
            # Link the last hosts to s3
            else:
                self.addLink(switches[2], tempHost)

        # Create three links between s1 and s2 with constrains
        for i in range(3):
            self.addLink(switches[0], switches[1], cls=TCLink, bw=100, delay='5ms')

        # Create two links between s2 and s3 with constrains
        for i in range(2):
            self.addLink(switches[1], switches[2], cls=TCLink, bw=50, delay='10ms')



class TutorialTopology( Topo ):

    def build( self ):

    # add switches
        for s in range(0, 2):
            self.addSwitch( "s{}".format(s+1) )

    # add hosts to s1
        for h in range(0, 5):
            host = self.addHost( "h{}".format(h+1) )
            self.addLink( host, 's1' )

    # add hosts to s2
        for h in range(0, 5):
            host = self.addHost( "h{}".format(h+6) )
            self.addLink( host, 's2' )

    # link the switches
        self.addLink( 's1', 's2', cls=TCLink, bw=50, delay='30ms', loss=10 )


topos = {'myTopo': (lambda: MyTopo()), 'tutorialTopology': ( lambda: TutorialTopology() ) }

