
#
# Command line usage:
# $ python3 dns-client.py --help
#

import json
import sys
import click

# import from the 21 Developer Library
from two1.commands.config import Config
from two1.wallet import Wallet
from two1.bitrequests import BitTransferRequests

# set up bitrequest client for BitTransfer requests
wallet = Wallet()
username = Config().username
requests = BitTransferRequests(wallet, username)

DNSCLI_VERSION = '0.1'
DEFAULT_ENDPOINT = 'http://[::]:12005/'


@click.group()
@click.option('--endpoint', '-e',
              default=DEFAULT_ENDPOINT,
              metavar='STRING',
              show_default=True,
              help='API endpoint URI')
@click.option('--debug', '-d',
              is_flag=True,
              help='Turns on debugging messages.')
@click.version_option(DNSCLI_VERSION)
@click.pass_context
def main(ctx, endpoint, debug):
    """
    Command-line Interface for the DDNS API service.
    """
    if ctx.obj is None:
        ctx.obj = {}

    ctx.obj['endpoint'] = endpoint


@click.command(name='register')
@click.argument('name')
@click.argument('ips', nargs=-1)
@click.pass_context
def cmd_register(ctx, name, ips):
    """
    Register a host with any ip addresses specified.
    """
    pubkey = wallet.get_message_signing_public_key()
    pkh = pubkey.address()
    print("Registering with key %s" % (pkh,))

    addresses = []
    for ip in ips:
        addresses.append(ip)

    req_obj = {
        'name': name,
        'pkh': pkh,
        'addresses': addresses,
    }

    sel_url = ctx.obj['endpoint'] + 'dns/register'
    body = json.dumps(req_obj)

    sig_str = wallet.sign_bitcoin_message(body, pkh)
    headers = {
        'Content-Type': 'application/json',
        'X-Bitcoin-Sig': sig_str,
    }
    answer = requests.post(url=sel_url.format(), headers=headers, data=body)
    print(answer.text)


@click.command(name='status')
@click.argument('name')
@click.pass_context
def cmd_status(ctx, name):
    """
    Get the status for the host name specified.
    """
    req_obj = {
        'name': name,
    }

    sel_url = ctx.obj['endpoint'] + 'dns/status'
    body = json.dumps(req_obj)

    headers = {'Content-Type': 'application/json'}
    answer = requests.post(url=sel_url.format(), headers=headers, data=body)
    print(answer.text)


@click.command(name='renew')
@click.argument('name')
@click.pass_context
def cmd_update(ctx, name):
    """
    Renew the existing record for 30 days.
    """
    req_obj = {'name': name}
    body = json.dumps(req_obj)

    sel_url = ctx.obj['endpoint'] + 'dns/renew'
    headers = {
        'Content-Type': 'application/json'
    }
    answer = requests.post(url=sel_url.format(), headers=headers, data=body)
    print(answer.text)


@click.command(name='delete')
@click.argument('name')
@click.argument('pkh')
@click.pass_context
def cmd_delete(ctx, name, pkh):
    """
    Delete an existing record.
    """
    req_obj = {
        'name': name,
        'pkh': pkh
    }

    body = json.dumps(req_obj)
    sig_str = wallet.sign_bitcoin_message(body, pkh)
    if not wallet.verify_bitcoin_message(body, sig_str, pkh):
        print("Cannot self-verify message")
        sys.exit(1)

    sel_url = ctx.obj['endpoint'] + 'dns/delete'
    headers = {
        'Content-Type': 'application/json',
        'X-Bitcoin-Sig': sig_str,
    }
    answer = requests.post(url=sel_url.format(), headers=headers, data=body)
    print(answer.text)

main.add_command(cmd_register)
main.add_command(cmd_status)
main.add_command(cmd_update)
main.add_command(cmd_delete)

if __name__ == "__main__":
    main()
