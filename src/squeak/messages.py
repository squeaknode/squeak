import squeak
from bitcoin.messages import msg_version as bitcoin_msg_version
from bitcoin.messages import msg_verack as bitcoin_msg_verack
from bitcoin.messages import msg_addr as bitcoin_msg_addr
from bitcoin.messages import msg_alert as bitcoin_msg_alert
from bitcoin.messages import msg_inv as bitcoin_msg_inv
from bitcoin.messages import msg_getdata as bitcoin_msg_getdata
from bitcoin.messages import msg_notfound as bitcoin_msg_notfound
from bitcoin.messages import msg_getheaders as bitcoin_msg_getheaders
from bitcoin.messages import msg_headers as bitcoin_msg_headers
from bitcoin.messages import msg_getaddr as bitcoin_msg_getaddr
from bitcoin.messages import msg_ping as bitcoin_msg_ping
from bitcoin.messages import msg_pong as bitcoin_msg_pong
from bitcoin.messages import msg_reject as bitcoin_msg_reject
from bitcoin.net import PROTO_VERSION


USER_AGENT = (b'/python-squeak:' +
              squeak.__version__.encode('ascii') + b'/')


class msg_version(bitcoin_msg_version):

    def __init__(self, protover=PROTO_VERSION, user_agent=USER_AGENT):
        super(msg_version, self).__init__(protover=protover)
        self.strSubVer = user_agent


class msg_verack(bitcoin_msg_verack):
    pass


class msg_addr(bitcoin_msg_addr):
    pass


class msg_alert(bitcoin_msg_alert):
    pass


class msg_inv(bitcoin_msg_inv):
    pass


class msg_getdata(bitcoin_msg_getdata):
    pass


class msg_notfound(bitcoin_msg_notfound):
    pass


class msg_getheaders(bitcoin_msg_getheaders):
    pass


class msg_headers(bitcoin_msg_headers):
    pass


class msg_getaddr(bitcoin_msg_getaddr):
    pass


class msg_ping(bitcoin_msg_ping):
    pass


class msg_pong(bitcoin_msg_pong):
    pass


class msg_reject(bitcoin_msg_reject):
    pass
