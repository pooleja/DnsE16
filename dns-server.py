import json
import srvdb
import re
import base58
import ipaddress
import subprocess
import time
import logging
import os
import psutil
import yaml
from httputil import http200, http400, http403, http404, http500

# import flask web microframework
from flask import Flask
from flask import request
from flask import send_from_directory

# import from the 21 Developer Library
from two1.wallet import Wallet
from two1.bitserv.flask import Payment

# Logging
logger = logging.getLogger('werkzeug')

# Config from file.
server_config = json.load(open("dns-server.conf"))
DNS_SERVER1 = server_config["DNS_SERVER1"]
NSUPDATE_KEYFILE = server_config["NSUPDATE_KEYFILE"]
NSUPDATE_LOG = server_config["NSUPDATE_LOG"]
nsupdate_logging = server_config["NSUPDATE_LOGGING"]

db = srvdb.SrvDb(server_config["DB_PATHNAME"])

app = Flask(__name__)
app.debug = True

wallet = Wallet()
payment = Payment(app, wallet)

name_re = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9-]*$")
name_ns_re = re.compile(r"^ns[0-9]+")


def valid_name(name):
    """
    Check for valid name.
    """
    if not name or len(name) < 1 or len(name) > 64:
        return False
    if not name_re.match(name):
        return False
    if name.count('.') > 1:
        return False
    return True


def is_subdomain(name):
    """
    Checks if this is a subdomain.
    """
    return name.count('.') > 0


def reserved_name(name):
    """
    Check for reserved name.
    """
    if name_ns_re.match(name):
        return True
    return False


def nsupdate_cmd(name, domain, host_records):
    """
    Create nsupdate command line.
    """
    pathname = "%s.%s." % (name, domain)

    cmd = "server %s\n" % (DNS_SERVER1,)
    cmd += "zone %s.\n" % (domain,)
    cmd += "update delete %s\n" % (pathname,)

    for rec in host_records:
        cmd += "update add %s %d %s %s\n" % (pathname, rec[4], rec[2], rec[3])

    cmd += "show\n"
    cmd += "send\n"

    return cmd.encode('utf-8')


def nsupdate_exec(name, domain, host_records):
    """
    Run nsupdate command.
    """
    nsupdate_input = nsupdate_cmd(name, domain, host_records)
    args = [
        "/usr/bin/nsupdate",
        "-k", NSUPDATE_KEYFILE,
        "-v",
    ]
    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        outs, errs = proc.communicate(input=nsupdate_input, timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        outs, errs = proc.communicate(input=nsupdate_input)

    if nsupdate_logging:
        with open(NSUPDATE_LOG, 'a') as f:
            f.write("timestamp %lu\n" % (int(time.time()),))
            f.write(outs.decode('utf-8') + "\n")
            f.write(errs.decode('utf-8') + "\n")
            f.write("---------------------------------------------\n")

    if proc.returncode is None or proc.returncode != 0:
        return False
    return True


def parse_hosts(name, domain, in_obj):
    """
    Parse the host list and params from input.
    """
    host_records = []
    try:
        if 'hosts' not in in_obj:
            return host_records

        hosts = in_obj['hosts']
        for host in hosts:
            rec_type = host['rec_type']
            ttl = int(host['ttl'])

            if ttl < 30 or ttl > (24 * 60 * 60 * 7):
                return "Invalid TTL"

            if rec_type == 'A':
                address = ipaddress.IPv4Address(host['address'])
            elif rec_type == 'AAAA':
                address = ipaddress.IPv6Address(host['address'])
            else:
                return "Invalid rec type"

            host_rec = (name, domain, rec_type, str(address), ttl)
            host_records.append(host_rec)

    except:
        return "JSON validation exception"

    return host_records


def store_host(name, domain, days, pkh, host_records):
    """
    Add the host to the db and run nsupdate to add it to the DNS server.
    """
    # Add to database.  Rely on db to filter out dups.
    try:
        logger.debug("Storing info: {} {} {} {}".format(name, domain, days, pkh))
        db.add_host(name, domain, days, pkh)
        if len(host_records) > 0:
            if not nsupdate_exec(name, domain, host_records):
                return http500("nsupdate failure")
            db.update_records(name, domain, host_records)
    except:
        return http400("Host addition rejected.  Host may already be registered.")

    return http200("Host record successfully stored for 30 days.")


def verify_subdomain_ownership(name, pkh):
    """
    Verifies the top level domain is owned by the same key for the subdomain that is trying to be registered.
    """
    index = name.find(".")
    topDomain = name[index + 1:]
    hostinfo = db.get_host(topDomain, "21")

    if hostinfo is None:
        raise PermissionError("Please register top level domain first before trying to register a subdomain.")

    if hostinfo['pkh'] != pkh:
        raise PermissionError("Invalid key used to try and register subdomain")


@app.route('/dns/register', methods=['POST'])
@payment.required(10000)
def cmd_host_register_21():
    """
    Perform a simple registration from the client on the *.21 TLD, default to 30 days.
    """
    # Parse JSON body w/ API params
    try:
        body = request.data.decode('utf-8')
        in_obj = json.loads(body)
    except:
        return http400("JSON Decode failed. Check JSON POST data structure on request.")

    # Validate expected fields
    try:
        name = in_obj['name']
        addresses = in_obj['addresses']
        pkh = in_obj['pkh']
        domain = "21"
        days = 30

        # Strip the .21 from the end of the name if the user specified it
        if name.endswith(".21"):
            name = name[0:len(name) - 3]

        if not valid_name(name):
            return http400("Invalid name param: {}".format(name))
        if days < 1 or days > 365:
            return http400("Invalid days param: {}".format(days))
        if not db.valid_domain(domain):
            return http404("Domain not found: {}".format(domain))

        # Make sure they own the top domain if they are trying to register a subdomain
        if is_subdomain(name):
            verify_subdomain_ownership(name, pkh)

    except Exception as err:
        logger.error("Failure: {0}".format(err))
        return http400("Invalid name / ip / pkh supplied")

    # Validate the signature on the message
    try:
        validate_sig(body, request.headers.get('X-Bitcoin-Sig'), pkh)
    except PermissionError as err:
        logger.error("Failure: {0}".format(err))
        return http403(err)

    try:
        # Validate and collect host records
        host_records = []
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if isinstance(ip, ipaddress.IPv4Address):
                rec_type = 'A'
            elif isinstance(ip, ipaddress.IPv6Address):
                rec_type = 'AAAA'
            else:
                return http500("Unable to determine type of IP address provided: {}".format(ip))

            host_rec = (name, domain, rec_type, str(address), 300)
            host_records.append(host_rec)
    except:
        return http400("Invalid IP address supplied: {}".format(addresses))

    # Check against reserved host name list
    if reserved_name(name):
        return http400("Reserved name.  Name not available for registration.")

    return store_host(name, domain, days, pkh, host_records)


def validate_sig(body, sig_str, pkh):
    """
    Validate the signature on the body of the request - throws exception if not valid.
    """
    # Check permission to update
    if (pkh is None):
        raise PermissionError("pkh not found.")

    # Validate the pkh format
    base58.b58decode_check(pkh)
    if (len(pkh) < 20) or (len(pkh) > 40):
        raise PermissionError("Invalid pkh")

    try:
        if not sig_str:
            raise PermissionError("X-Bitcoin-Sig header not found.")
        if not wallet.verify_bitcoin_message(body, sig_str, pkh):
            raise PermissionError("X-Bitcoin-Sig header not valid.")
    except Exception as err:
        logger.error("Failure: {0}".format(err))
        raise PermissionError("X-Bitcoin-Sig header validation failed.")

    return True


@app.route('/dns/delete', methods=['POST'])
@payment.required(1000)
def cmd_host_delete():
    """
    Validate ownership and delete a host.
    """
    # Parse JSON body w/ API params
    try:
        body = request.data.decode('utf-8')
        in_obj = json.loads(body)
    except Exception as err:
        logger.error("Failure: {0}".format(err))
        return http400("JSON Decode failed. Check JSON POST data structure on request.")

    # Validate JSON object basics
    try:
        if 'name' not in in_obj or 'pkh' not in in_obj:
            return http400("Missing name/pkh")

        domain = "21"
        name = in_obj['name']
        pkh = in_obj['pkh']

        if (not valid_name(name)):
            return http400("Invalid name param: {}".format(name))

        if not db.valid_domain(domain):
            return http404("Domain not found")

    except Exception as err:
        logger.error("Failure: {0}".format(err))
        return http400("JSON validation exception")

    # Verify host exists and pkh matches
    try:
        hostinfo = db.get_host(name, domain)
        if hostinfo is None:
            return http404("Name parameter not found: {}".format(name))

        # Validate the submitted pkh matches the one in the db
        if (pkh != hostinfo['pkh']):
            return http403("pkh does not match existing record.")

    except Exception as err:
        logger.error("Failure: {0}".format(err))
        return http500("DB Exception - get host")

    # Validate the signature on the message
    try:
        validate_sig(body, request.headers.get('X-Bitcoin-Sig'), pkh)
    except PermissionError as err:
        logger.error("Failure: {0}".format(err))
        return http403(err)

    # Remove from database.  Rely on db to filter out dups.
    try:
        if not nsupdate_exec(name, domain, []):
            http500("nsupdate failure")
        db.delete_host(name, domain)
    except Exception as err:
        logger.error("Failure: {0}".format(err))
        return http400("DB Exception - delete host")

    return http200("Record successfully deleted.")


@app.route('/dns/status', methods=['POST'])
@payment.required(1000)
def cmd_host_status():
    """
    Gets the stats of the specified registered name.
    """
    # Validate JSON body w/ API params
    try:
        body = request.data.decode('utf-8')
        in_obj = json.loads(body)
    except:
        return http400("JSON Decode failed")

    try:
        if 'name' not in in_obj:
            return http400("Missing name parameter.")

        name = in_obj['name']
        if not valid_name(name):
            return http400("Invalid name")
    except:
        return http400("JSON validation exception")

    # Get info about the requested name
    try:
        hostinfo = db.get_host(name, "21")
        if hostinfo is None:
            return http404("Unknown name")
    except:
        return http500("DB Exception")

    # Remove the pkh from return obj.
    del hostinfo['pkh']

    # Add display dates
    hostinfo['create_display_date'] = time.ctime(hostinfo['create'])
    hostinfo['expire_display_date'] = time.ctime(hostinfo['expire'])

    ret = json.dumps({"success": True, "hostinfo": hostinfo}, indent=2)
    return (ret, 200, {'Content-length': len(ret), 'Content-type': 'application/json'})


@app.route('/dns/renew', methods=['POST'])
@payment.required(10000)
def cmd_host_update():
    """
    Renew the name for +30 days.
    """
    # Validate JSON body w/ API params
    try:
        body = request.data.decode('utf-8')
        in_obj = json.loads(body)
    except:
        return http400("JSON Decode failed")

    try:
        if 'name' not in in_obj:
            return http400("Missing name parameter.")

        name = in_obj['name']
        if not valid_name(name):
            return http400("Invalid name")
    except:
        return http400("JSON validation exception")

    # Get info about the requested name
    try:
        hostinfo = db.get_host(name, "21")
        if hostinfo is None:
            return http404("Unknown name")
    except:
        return http500("DB Exception")

    # Calculate the expire date for +30 days
    currentExpire = hostinfo['expire']
    newExpire = currentExpire + (30 * 24 * 60 * 60)
    hostinfo['expire'] = newExpire
    db.update_host_expiration(name, "21", newExpire)

    # Remove the pkh from return obj.
    del hostinfo['pkh']

    # Add display dates
    hostinfo['create_display_date'] = time.ctime(hostinfo['create'])
    hostinfo['expire_display_date'] = time.ctime(hostinfo['expire'])

    ret = json.dumps({"success": True, "hostinfo": hostinfo, "message": "Added 30 days to host expire time."}, indent=2)
    return (ret, 200, {'Content-length': len(ret), 'Content-type': 'application/json'})


@app.route('/client')
def client():
    """Provide the client file to any potential users."""
    return send_from_directory('./', 'dns-client.py')


if __name__ == '__main__':
    import click

    @click.command()
    @click.option("-d", "--daemon", default=False, is_flag=True, help="Run in daemon mode.")
    @click.option("-l", "--log", default="ERROR", help="Logging level to use (DEBUG, INFO, WARNING, ERROR, CRITICAL)")
    def run(daemon, log):
        """
        Run the server.
        """
        # Set logging level
        numeric_level = getattr(logging, log.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: %s' % log)
        logging.basicConfig(level=numeric_level)

        if daemon:
            pid_file = './DnsE16.pid'
            if os.path.isfile(pid_file):
                pid = int(open(pid_file).read())
                os.remove(pid_file)
                try:
                    p = psutil.Process(pid)
                    p.terminate()
                except:
                    pass
            try:
                p = subprocess.Popen(['python3', 'dns-server.py'])
                open(pid_file, 'w').write(str(p.pid))
            except subprocess.CalledProcessError:
                raise ValueError("error starting dns-server.py daemon")
        else:

            logger.info("Server running...")
            app.run(host='::', port=12005)

    run()
