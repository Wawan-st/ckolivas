import tornado
from tornado import gen
import time
import datetime
from tornado.tcpclient import TCPClient

@gen.coroutine
def start(host, port, user):
    transport = yield TCPClient().connect(host, port)
    yield transport.write('{"params": ["suprminer/1.6"], "id": 1, "method": "mining.subscribe"}\n')
    resp = yield transport.read_until('\n')
    print 1,host, datetime.datetime.now(), "#", resp, "#", len(resp),
    yield transport.write('{"params": ["%s", "password"], "id": 2, "method": "mining.authorize"}\n' % user)
    jid = 3
    while True:
        resp = yield transport.read_until('\n')
        if len(resp) < 10:
            print host, datetime.datetime.now(), "#", resp, "#", len(resp) , resp.encode('hex')
        else:
            print host, datetime.datetime.now(), "#", resp, "#", len(resp)
        jid += 1

def on_ready():
        start("hdac.f2pool.com", 5770, 'HKqKACjBD9w7V6FqbEHinQEhSAmU43bEpV.1')

if __name__ == '__main__':
        tornado.ioloop.IOLoop.instance().add_callback(on_ready)
        tornado.ioloop.IOLoop.instance().start()
