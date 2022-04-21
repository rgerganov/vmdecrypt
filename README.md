# Overview

`vmdecrypt` decrypts multicast MPEG TS streams encrypted with Verimatrix VCAS ([CAID=0x5601](https://en.wikipedia.org/wiki/Conditional_access#Digital_systems)) and serve them on HTTP. You also need the corresponding channel key for each of the encrypted streams. The channel key is an AES key which is used for decrypting the ECM packets. The ECM packets contain 2 AES keys which are used for decrypting the TS packets. The ECM keys are rotated every 10sec. but the channel key is usually rotated every 24h and can be easily shared.

I presented `vmdecrypt` at BSides Sofia, you can watch the recording [here](https://www.youtube.com/watch?v=7JTUQgBlSSU) (in Bulgarian).

# Obtaining channel keys

First you need an STB (or some other device) which can play the encrypted streams. Get root access to the STB and find the RSA key which is used for signing the payload sent to VCAS. Then you can obtain the channel keys with the following protocol:

1. Send `CreateSessionKey` command to VCAS and pass the STB MAC address. The VCAS returns an RC4 session key (16 bytes) and a timestamp. This communication is done over a TLS socket.
2. Send `GetAllChannelKeys` command to VCAS with the following payload: `RC4_Encrypt(RSA_Sign(MD5(timestamp)))` using the RC4 session key and the RSA key from the STB. The VCAS returns all channel keys encrypted with the RC4 session key. This communication is done over plain socket.

# Usage
```
go get -u github.com/rgerganov/vmdecrypt
vmdecrypt -i eth0 -a 192.168.1.10:8080 -c https://example.com/channels.json
```

Here `eth0` is the multicast interface, the channels file will be downloaded from `https://example.com/channels.json` and the HTTP server will be started at `192.168.1.10:8080`.
When started, `http://192.168.1.10:8080/channels.m3u` returns an M3U playlist with all channels.
