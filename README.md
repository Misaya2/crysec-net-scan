# crysec
just a simple syn scanner in c. i wrote this for some local network testing.

### how to run
you need libpcap:
`sudo apt install libpcap-dev`

compile:
`gcc crysec.c -o crysec -lpcap -lpthread`

usage:
`sudo ./crysec <ip> <ports> <iface>`

### example
`sudo ./crysec 192.168.0.100 500 enp0s3`

### todo
- maybe fix some random segfaults
- add better error handling
- clean up the banner grabbing part
