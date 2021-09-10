#!/usr/bin/python
import os
import signal as sig
import sys
commands = """
	go build
	sudo setcap cap_net_admin=eip ~/Languages/Go/tigo/tigo
	./tigo &
	sudo ip addr add 192.168.0.1/24 dev tun0
 	sudo ip link set up dev tun0
    sudo arp -s 192.168.0.2 ff:ff:ff:ff:ff:f1
"""


def handler():
    os.system('pkill tigo')
    sys.exit(0)


def main():
    cmds = [cmd for cmd in commands.split('\n') if not cmd.isspace()]
    for cmd in cmds:
        os.system(cmd)


if __name__ == '__main__':
    try:
        main()
        while True:
            pass
    except KeyboardInterrupt:
        os.system("pkill tigo")
    # sig.signal(sig.SIGINT, handler())
    # while True:
    #     pass
