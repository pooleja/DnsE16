
# DnsE16
====================================

This project is adapted from Jeff Garzik's 21 playground21 DNS prototype.  See [here for the details.](https://github.com/jgarzik/playground21/tree/master/dns)

## Overview

The DnsE16 service allows anyone running on the 21 network to use host names instead of IP addresses to keep track of servers.  Right now, you would need to run commands like:

```
$ 21 buy http://10.248.12.34:2001/service/endpoint
```

Using the new service, you could set it up so the following can be done with a host name instead:

```
$ 21 buy http://my-endpoint.21/service/endpoint
```

## How to Use

### DNS Setup

To utilize the service, you first need to set the DNS on your system to point to the DNS server 10.244.113.158.  This can be done a number of ways, so look that up according to your OS.

You can verify that DNS can't resolve the DnsE16 server by tring to ping the nameserver:
```
$ ping ns1.21
ping: unknown host ns1.21
```

In my case, I updated resolvconf head file:
```
$ sudo vi /etc/resolvconf/resolv.conf.d/head
```

Ignore messages and add this line:
```
nameserver 10.244.113.158
```

Restart resolvconf:
```
$ sudo resolvconf -u
```

Verify it is using the new DNS Nameserver:
```
$ ping ns1.21
PING ns1.21 (10.244.113.158) 56(84) bytes of data.
64 bytes from 10.244.113.158: icmp_seq=1 ttl=64 time=0.038 ms
```

### Register Your Service

The first thing you will want to do is get the client:
```
$ 21 buy http://dns.21:12005/client -o client.py
```
This will download the client.py file into the current directory.

Next, you can use the client to see if a name is currently available:
```
$ python3 client.py -e http://dns.21:12005/ status mynewname
{
  "success": false,
  "message": "Unknown name"
}
```
Here you can see that it is an unknown name, so it can now be registered (use the IP address from '21 market status'):
```
$ python3 client.py -e http://dns.21:12005/ register mynewname 10.244.113.158
Registering with key MMMMMMMMMBBBBBBBBBBBB
{
  "success": true,
  "message": "Host record successfully stored for 30 days."
}
```
You need to save the key used for registration (e.g. 'MMMMMMMMMBBBBBBBBBBBB') if you ever want the ability to edit/delete it in the future.  This will prevent someone else from modifying your registered name.

Now you should be able to ping your service:
```
$ ping mynewname.21
PING mynewname.21 (10.244.113.158) 56(84) bytes of data.
64 bytes from 10.244.113.158: icmp_seq=1 ttl=64 time=0.020 ms
```

You can get the status to see how long it will be registered for:
```
$ python3 client.py -e http://dns.21:12005/ status mynewname
{
  "hostinfo": {
    "expire_display_date": "Wed Sep 28 19:06:52 2016",
    "domain": "21",
    "create_display_date": "Mon Aug 29 19:06:52 2016",
    "name": "mynewname",
    "expire": 1475089612,
    "create": 1472497612
  },
  "success": true
}
```

You can renew it to add more time before it expires:
```
$ python3 client.py -e http://dns.21:12005/ renew mynewname
{
  "hostinfo": {
    "expire_display_date": "Fri Oct 28 19:06:52 2016",
    "domain": "21",
    "create_display_date": "Mon Aug 29 19:06:52 2016",
    "name": "mynewname",
    "expire": 1477681612,
    "create": 1472497612
  },
  "success": true,
  "message": "Added 30 days to host expire time."
}
```
You can see it went from Sept to Oct expire date above.

You can also delete it if you want to remove it from the DNS system:
```
$ python3 client.py -e http://dns.21:12005/ delete mynewname MMMMMMMMMBBBBBBBBBBBB
{
  "success": true,
  "message": "Record successfully deleted."
}
```

After deletion you will see that you can no longer ping it:
```
$ ping mynewname.21
ping: unknown host mynewname.21
```
