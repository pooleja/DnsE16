
import json


def httpjson(val):
    """
    Create the result payload from json for a success.
    """
    body = json.dumps(val, indent=2)
    return (body, 200, {
        'Content-length': len(body),
        'Content-type': 'application/json',
    })


def http400(msg):
    """
    Create the result payload for a 400 error.
    """
    if not msg:
        msg = "Invalid request"
    return (msg, 400, {'Content-Type': 'text/plain'})


def http404(msg):
    """
    Create the result payload for a 404 error.
    """
    if not msg:
        msg = "Not found"
    return (msg, 404, {'Content-Type': 'text/plain'})


def http500(msg):
    """
    Create the result payload for a 500 error.
    """
    if not msg:
        msg = "Internal server error"
    return (msg, 500, {'Content-Type': 'text/plain'})
