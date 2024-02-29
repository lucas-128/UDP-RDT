from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink

TOPOS = {"mytopo": (lambda hosts,connection_loss: mytopo(hosts,connection_loss))}


class mytopo(Topo):
    "Single switch connected to n hosts."

    def build(self, n=4, conn_loss=0):
        hosts_dict = {}
        for x in range(1, n+2):
            hosts_dict["host{0}".format(str(x))] = self.addHost("h%s" % (str(x)))

        switch = self.addSwitch("s1")
        for host in hosts_dict.keys():
            self.addLink(hosts_dict[host], switch, cls=TCLink, loss=conn_loss)


def Q1_a(n_clients, connection_loss):
    "Create and test a simple network"
    topo = mytopo(n_clients, connection_loss)
    net = Mininet(topo)
    # net.start()
    # net.stop()


if __name__ == "__main__":
    # Tell mininet to print useful information

    Q1_a(10,1)