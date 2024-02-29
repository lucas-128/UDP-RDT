import argparse
import netifaces as ni



class Arguments:
    def __init__(self, action):
        self._args = self.__parse(action)

    def __parse(self, action):
        parser = argparse.ArgumentParser()
        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            "-v", "--verbose", action="store_true", help="increase output verbosity"
        )
        group.add_argument(
            "-q", "--quiet", action="store_true", help="decrease output verbosity"
        )
        if action == "download" or action =="upload":
            parser.add_argument("-P","--protocol",choices=["sw","sr"],default="sw", help="communication protocol (sw or sr)")
            parser.add_argument(
            "-H", "--host", default=self._ip_default(), help="server IP address")
            parser.add_argument(
            "-p", "--port", type=int, default="9090", help="server port")
        elif action == "start-server":
            parser.add_argument(
            "-H", "--host", default=self._ip_default(), help="service IP address")
            parser.add_argument(
            "-p", "--port", type=int, default="9090", help="server port")
        
        if action == "upload":
            parser.add_argument("-s", "--src", default=".", help="source file path")
        elif action =="download":
            parser.add_argument(
                "-d", "--dst", default=".", help="destination file path"
            )
        elif action =="start-server":
            parser.add_argument(
                "-s", "--storage", default=".", help="storage dir path"
            )
        if action == "download" or action =="upload":
            parser.add_argument("-n","--name",default="duck_maul.jpg",help="file name",)

        return parser.parse_args()

    def get_args(self):
        return self._args

    def get_arg(self,arg):
        map = vars(self.get_args())
        return map[arg]
    
    def _ip_default(self):
        interfaces = ni.interfaces()
        i = [interface for interface in interfaces if 'eth0' in interface]
        if len(i)>0:
            ip = ni.ifaddresses(i[0])[ni.AF_INET][0]['addr']
        else:
            ip = "127.0.0.1"    
        return ip

