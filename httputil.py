
import json


def http200(msg):
    """
    Create the result payload from json for a success.
    """
    ret = json.dumps({"success": True, "message": msg}, indent=2)
    return (ret, 200, {'Content-length': len(ret), 'Content-type': 'application/json'})


def http400(msg):
    """
    Create the result payload for a 400 error.
    """
    if not msg:
        msg = "Invalid request"
    ret = json.dumps({"success": False, "message": msg}, indent=2)
    return (ret, 400, {'Content-length': len(ret), 'Content-Type': 'application/json'})


def http403(msg):
    """
    Create the result payload for a 403 error.
    """
    if not msg:
        msg = "Not found"
    ret = json.dumps({"success": False, "message": msg}, indent=2)
    return (ret, 403, {'Content-length': len(ret), 'Content-Type': 'application/json'})


def http404(msg):
    """
    Create the result payload for a 404 error.
    """
    if not msg:
        msg = "Not found"
    ret = json.dumps({"success": False, "message": msg}, indent=2)
    return (ret, 404, {'Content-length': len(ret), 'Content-Type': 'application/json'})


def http500(msg):
    """
    Create the result payload for a 500 error.
    """
    if not msg:
        msg = "Internal server error"
    ret = json.dumps({"success": False, "message": msg}, indent=2)
    return (ret, 500, {'Content-length': len(ret), 'Content-Type': 'application/json'})
