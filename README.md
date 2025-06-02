# Confessions

This is an end-to-end encrypted and peer-to-peer voice program
using the sanctum protocol as its transport layer.

For details on how the underlying tunnels works see
<a href="https://github.com/jorisvink/sanctum/blob/master/docs/crypto.md">docs/crypto.md</a> in the sanctum repository.

## Building

Confessions builds and works at least on MacOS and Linux.

You need to have the following installed on your system:

- opus
- portaudio
- libsodium
- libkyrka (https://github.com/jorisvink/libkyrka)

Once you have those, building is easy:

```
$ make
# make install
```

### Modes

You can use confessions in three different modes, **direct**, **cathedral**
or **liturgy** mode.

In the **direct** mode you connect directly to your peer and perform
key offers under the shared secret, this is much like sanctum its
tunnel mode.

In the **cathedral** mode you first connect to a cathedral to discover
your peer and fallback to peer-to-peer once discovered (and if capable).

In the **liturgy** mode you autodiscover peers in the same group and
automatically establish e2e tunnels to them, effectively giving you
a group conversation.

When using a cathedral (both **cathedral** and **liturgy** mode) confessions
will use the default flock domain *0a* unless otherwise specified with
the -d option.

## Usage

```
Usage: confessions [mode] [opts] [ip:port]
Mode choices:
  direct          - Direct tunnel between two peers.
  cathedral       - Use a cathedral to do peer discovery.
  liturgy         - Use autodiscovery via cathedral.

Generic options:
  -s <path>       - The shared secret or catehdral secret

Direct specific options:
  -b <ip:port>    - Bind to the given ip:port

Cathedral specific options:
  -k <path>       - The device KEK
  -f <flock>      - Hexadecimal flock ID
  -d <domain>     - Hexadecimal flock domain
  -i <identity>   - Hexadecimal client ID
  -t <tunnel>     - Hexadecimal tunnel ID

Liturgy specific options:
  -g <group>      - The liturgy group to join

In cathedral mode, the tunnel given specifies who you want
to talk too. If you have two devices (01 and 02) and you
want to establish a voice channel between these you use
tunnel 0x0102 on device 01 and tunnel 0x0201 on device 02.

In liturgy mode, the tunnel ID (-t) only contains your
tunnel end point, so using the same example as before
you specify -t 0x01 in this mode.
```
