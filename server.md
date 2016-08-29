# Setting up Bind

#### Install bind9.
```
$ apt-get install bind9
```

#### Update the named.conf.options
You want to forward any unknown requests to Google DNS
```
$ sudo vi /etc/bind/named.conf.options
```
Uncomment:
```
forwarders {
 8.8.8.8;
 8.8.4.4;
};
```


#### Configure the access key
```
$ dnssec-keygen -a HMAC-MD5 -b 512 -n USER james.esixteen.co.
```
This will take a while...

Add a new keys.conf file:
```
$ sudo vi /etc/bind/keys.conf
```
Add the secret from the generated *.key file:
```
key james.esixteen.co. {
        algorithm HMAC-MD5;
        secret "BBBBBBBBBBBB/IwVEZrjXQ7z2v+sA AAAAAAAAAAAAA==";
};
```

Add the keys conf to the named.conf file:
```
$ sudo vi /etc/bind/named.conf
```
Insert this line:
```
include "/etc/bind/keys.conf";
```

#### Update the conf.local:
```
$ sudo vi /etc/bind/named.conf.local
```

```
zone "21." {
             type master;
             file "/var/lib/bind/db.21";
	     allow-update {
                key james.esixteen.co.;
             };
        };
```

#### Add the new zone file
```
$ sudo vi /var/lib/bind/db.21
```
Insert the following:
```
$ORIGIN .
$TTL 604800	; 1 week
21			IN SOA	21. root.21. (
				27         ; serial
				604800     ; refresh (1 week)
				86400      ; retry (1 day)
				2419200    ; expire (4 weeks)
				604800     ; minimum (1 week)
				)
			NS	localhost.
			A	127.0.0.1
			AAAA	::1
$ORIGIN 21.
$TTL 300	; 5 minutes
```

#### Verify Configuration
```
$ sudo named-checkconf
```
This will show no output if it's ok.

#### Verify Zone file
```
$ named-checkzone 21 /etc/bind/db.21
zone 21/IN: loaded serial 27
OK
```

#### Restart bind
```
$ sudo service bind9 restart
```
