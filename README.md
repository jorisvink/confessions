# Confessions

This is an end-to-end encrypted and peer-to-peer voice program
using the sanctum protocol as its transport layer.

## Building

Confessions builds and works at least on MacOS and Linux.

You need to have the following installed on your system:

- opus
- portaudio
- libkyrka (https://github.com/jorisvink/libkyrka)

Once you have those, building is easy:

```
$ make
# make install
```

### Modes

You can use confessions in two modes, **direct** or **cathedral**.

In the **direct** mode you connect directly to your peer and perform
key offers under the shared secret, this is much like sanctum its
tunnel mode.

In the **cathedral** mode you first connect to a cathedral to discover
your peer and fallback to peer-to-peer once discovered (and if capable).

## Usage

```
Usage: confessions [mode] [opts] [ip:port]
Mode choices:
  direct          - Direct tunnel between two peers.
  cathedral       - Use a cathedral to do peer discovery.

Generic options:
  -s <path>       - The shared secret or catehdral secret

Direct specific options:
  -b <ip:port>    - Bind to the given ip:port

Cathedral specific options:
  -k <path>       - The device KEK
  -f <flock>      - Hexadecimal flock ID
  -i <identity>   - Hexadecimal client ID
  -t <tunnel>     - Hexadecimal tunnel ID

In cathedral mode, the tunnel given specifies who you want
to talk too. If you have two devices (01 and 02) and you
want to establish a voice channel between these you use
tunnel 0x0102 on device 01 and tunnel 0x0201 on device 02.
```
