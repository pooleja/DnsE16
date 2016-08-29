#!/bin/sh

FN=/home/james/dns.db

if [ -f $FN ]
then
	echo Database $FN already exists.  Will not overwrite
	exit 1
fi
sqlite3 $FN < dns.schema
