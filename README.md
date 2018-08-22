# python-libnetfilter-log

Python wrapper for `libnetfilter_log`.

Unlike other wrappers for `libnetfilter_log`, this implementation doesn't perform the `recv` loop for you. It simply wraps `libnetfilter_log` structures in convenient Python objects and gives you more control over calls to `libnetfilter_log` functions. This allows you to use `libnetfilter_log` with the `gevent` package, which isn't possible with other Python `libnetfilter_log` wrappers.

## Usage

```python
import libnetfilterlog
import socket
import struct

def handle_tcp(payload):
    src, dst = struct.unpack('HH', payload[:4])
    print '    tcp.src: %s' % src
    print '    tcp.dst: %s' % dst

def handle_udp(payload):
    src, dst = struct.unpack('HH', payload[:4])
    print '    udp.src: %s' % src
    print '    udp.dst: %s' % dst

def handle_ipv4(payload):
    ip_verlen = ord(payload[0])
    ip_ver = ip_verlen >> 4
    assert ip_ver == 4
    src = socket.inet_ntop(socket.AF_INET, payload[12:16])
    dst = socket.inet_ntop(socket.AF_INET, payload[16:20])
    print '    ipv4.src: %s' % src
    print '    ipv4.dst: %s' % dst
    protocol = ord(payload[9])
    hdrlen = (ip_verlen & 0x0f) * 4
    data = payload[hdrlen:]
    handler = {6: handle_tcp, 17: handle_udp}
    if protocol in handler:
        handler[protocol](data)

def handle_ipv6(payload):
    ip_verlen = ord(payload[0])
    ip_ver = ip_verlen >> 4
    assert ip_ver == 6
    src = socket.inet_ntop(socket.AF_INET6, payload[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, payload[24:40])
    print '    ipv6.src: %s' % src
    print '    ipv6.dst: %s' % dst
    protocol = ord(payload[6])
    data = payload[40:]
    handler = {6: handle_tcp, 17: handle_udp}
    if protocol in handler:
        handler[protocol](data)

def callback(data):
    try:
        print 'Received:'
        mac_bytes = data.get_packet_hw()
        mac_string = (':'.join(['%02x'] * len(mac_bytes)) %
                      struct.unpack("B" * len(mac_bytes), mac_bytes))
        print '    eth.src: %s' % mac_string
        payload = data.get_payload()
        ip_verlen = ord(payload[0])
        ip_ver = ip_verlen >> 4
        handler = {4: handle_ipv4, 6: handle_ipv6}
        if ip_ver in handler:
            handler[ip_ver](payload)
        print
    except Exception as e:
        print e

handle = libnetfilterlog.open()

handle.unbind_pf(socket.AF_INET)
handle.unbind_pf(socket.AF_INET6)

handle.bind_pf(socket.AF_INET)
handle.bind_pf(socket.AF_INET6)

group = handle.bind_group(1)
group.set_mode(libnetfilterlog.NFULNL_COPY_PACKET, 0xffff)
group.set_callback(callback)

try:
    sock = socket.fromfd(handle.fd(),
                         socket.AF_UNIX,
                         socket.SOCK_STREAM)
    while True:
        try:
            data = sock.recv(4096)
            handle.handle_packet(data)
        except socket.error as e:
            if e.errno is socket.errno.ENOBUFS:
                print 'Unable to hold processed packets'
                continue
            raise
finally:
    sock.close()

group.unbind()

handle.close()
```

## Methods

This sections lists the methods directly under the `libnetfilterlog` module.

#### `libnetfilterlog.open()`

Calls `nflog_open` and returns a `NetfilterLogHandle` object which wraps around the `struct nflog_handle` structure and its related functions. See the documentation for the `NetfilterLogHandle` class in the "Classes" section below for more details.

## Classes

This module lists the classes directly under the `libnetfilterlog` module as well as the methods under them.

### `NetfilterLogHandle`

Serves as a broker between user applications and the netfilterlog system. This class wraps around the `struct nflog_handle` structure and its associated functions.

#### `NetfilterLogHandle.bind_pf(family)`

Bind the handle to a given protocol family. Wraps around the `nflog_bind_pf` function.

**Parameters**
* `family`: protocol family to bind to the handle

#### `NetfilterLogHandle.unbind_pf(family)`

Unnind the handle to a given protocol family. Wraps around the `nflog_unbind_pf` function.

**Parameters**
* `family`: protocol family to bind to the handle

#### `NetfilterLogHandle.bind_group(number)`

Bind the handle to a specific group number. Wraps around the `nflog_bind_group` function.

**Parameters**
* `number`: the number of the group to bind to

**Returns**
* A `NetfilterLogGroupHandle` object

#### `NetfilterLogHandle.handle_packet(data)`

Method to be invoked whenever a packet is received from the file descriptor. Dispatches calls to the appropriate callbacks. Your application should call this after receiving a new packet. Wraps around the `nflog_handle_packet` function.

**Parameters**
* `data`: the data of the received packet

#### `NetfilterLogHandle.fd()`

Get the file descriptor associated with the handle. You can create a Python socket from this. The created Python socket should respect `gevent` scheduling after monkey-patching. Wraps around the `nflog_fd` function.

**Returns**
* A file descriptor for the netlink connection associated with the given log connection handle

#### `NetfilterLogHandle.close()`

Closes the handle and frees associated resources. Wraps around the `nflog_close` function.

### `NetfilterLogGroupHandle`

Serves as a broker between user applications and a netfilterlog group. This class wraps around the `struct nflog_g_handle` structure and its associated functions.

#### `NetfilterLogGroupHandle.set_callback(callback)`

Registers a callback function onto the group. Wraps around the `nflog_callback_register` function. The provided callback function is invoked whenever the `NetfilterLogHandle.handle_packet` method is invoked by the application.

The callback function shall receive a `NetfilterLogData` object whenever it is invoked.

**Parameters**
* `callback`: the callback function to be invoked

#### `NetfilterLogGroupHandle.set_mode(mode, range)`

Set the amount of packet data that netfilterlog copies to userspace. Wraps around the `nflog_set_mode` function.

The `mode` parameter should be one of the following:
* `libnetfilterlog.NFULNL_COPY_NONE`
* `libnetfilterlog.NFULNL_COPY_META `
* `libnetfilterlog.NFULNL_COPY_PACKET`

**Parameters**
* `mode`: the part of the packet that we are interested in
* `range`: size of the packet that we want to get

#### `NetfilterLogGroupHandle.set_timeout(timeout)`

Set the maximum time to push log buffer for this group. Wraps around the `nflog_set_timeout` function.

**Parameters**
* `timeout`: time to wait until the log buffer is pushed to userspace

#### `NetfilterLogGroupHandle.set_qthresh(qthresh)`

Set the maximum amount of logs in buffer for this group. Wraps around the `nflog_set_qthresh` function.

**Parameters**
* `qthresh`: maximum number of log entries

#### `NetfilterLogGroupHandle.set_nlbufsiz(nlbufsiz)`

Set the size of the nflog buffer for this group. Wraps around the `nflog_set_nlbufsiz` function.

**Parameters**
* `nlbufsiz`: the size of the nflog buffer

#### `NetfilterLogGroupHandle.set_flags(flags)`

Set the nflog flags for this group. Wraps around the `nflog_set_flags` function.

There are two existing flags:
* `libnetfilterlog.NFULNL_CFG_F_SEQ`
* `libnetfilterlog.NFULNL_CFG_F_SEQ_GLOBAL`

**Parameters**
* `flags`: flags that you want to set

#### `NetfilterLogGroupHandle.unbind()`

Unbind this group handle. Wraps around the `nflog_unbind_group` function.

### `NetfilterLogData`

Contains information about a logged packet. Wraps around the `struct nflog_data` structure and its associated functions.

#### `NetfilterLogData.get_hwtype()`

Get the hardware link layer type from logging data. Wraps around the `nflog_get_hwtype` function.

**Returns**
* The hardware link layer type

#### `NetfilterLogData.get_msg_packet_hwhdr()`

Get the hardware link layer header. Wraps around the `nflog_get_msg_packet_hwhdr` function.

**Returns**
* The hardware link layer header

#### `NetfilterLogData.get_packet_hw()`

Get hardware address. Wraps around the `nflog_get_packet_hw` function.

**Returns**
* The hardware address associated with the given packet

#### `NetfilterLogData.get_nfmark()`

Get the packet mark. Wraps around the `nflog_get_nfmark` function.

**Returns**
* The netfilter mark currently assigned to the logged packet

#### `NetfilterLogData.get_timestamp()`

Get the packet timestamp. Wraps around the `nflog_get_timestamp` function.

**Returns**
* A tuple containing the timestamp's seconds and microseconds components respectively

#### `NetfilterLogData.get_indev()`

Get the interface that the packet was received through. Wraps around the `nflog_get_indev` function.

**Returns**
* The index of the device the packet was received via (0 if unknown)

#### `NetfilterLogData.get_physindev()`

Get the physical interface that the packet was received. Wraps around the `nflog_get_physindev` function.

**Returns**
* The index of the physical device the packet was received via (0 if unknown)

#### `NetfilterLogData.get_outdev()`

Gets the interface that the packet will be routed out. Wraps around the `nflog_get_outdev` function.

**Returns**
* The index of the device the packet will be sent out (0 if unknown)

#### `NetfilterLogData.get_physoutdev()`

Get the physical interface that the packet output. Wraps around the `nflog_get_physoutdev` function.

**Returns**
* The index of physical interface that the packet output will be routed out (0 if unknown)

#### `NetfilterLogData.get_payload()`

Get payload of the logged packet. Wraps around the `nflog_get_payload` function.

**Returns**
* A string containing the payload of the logged packet

#### `NetfilterLogData.get_prefix()`

Get the logging string prefix. Wraps around the `nflog_get_prefix` function.

**Returns**
* The string prefix that is specified as argument to the iptables' NFLOG target

#### `NetfilterLogData.get_uid()`

Get the UID of the user that has generated the packet. Wraps around the `nflog_get_uid` function.

**Returns**
* The UID of the user that has genered the packet, if any

#### `NetfilterLogData.get_gid()`

Get the GID of the user the packet belongs to. Wraps around the `nflog_get_gid` function.

**Returns**
* The GID of the user that has genered the packet, if any

#### `NetfilterLogData.get_seq()`

Get the local nflog sequence number. Must be enabled via the `set_flags` method. Wraps around the `nflog_get_seq` function.

**Returns**
* The local nflog sequence number

#### `NetfilterLogData.get_seq_global()`

Get the global nflog sequence number. Must be enabled via the `set_flags` method. Wraps around the `nflog_get_seq_global` function.

**Returns**
* The global nflog sequence number
