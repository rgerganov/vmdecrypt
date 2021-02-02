`vmdecrypt` decrypts multicast MPEG TS streams encrypted with Verimatrix and serve them on HTTP

Usage:
```
go get -u github.com/rgerganov/vmdecrypt
vmdecrypt -i eth0 -a 192.168.1.10:8080 -c https://example.com/channels.json
```

Here `eth0` is the multicast interface, the channels file will be downloaded from `https://example.com/channels.json` and the HTTP server will be started at `192.168.1.10:8080`.
When started, `http://192.168.1.10:8080/channels.m3u` returns an M3U playlist with all channels.
