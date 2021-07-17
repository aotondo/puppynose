#brctl addbr br0
brctl addif br0 eth1
#ifdown br0
#ifup br0
/usr/bin/python3 /home/pi/puppynose/main.py
