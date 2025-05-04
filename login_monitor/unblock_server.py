# unblock_server.py
from flask import Flask, request
import json
import os

app = Flask(__name__)

BLACKLIST_FILE = "blacklist.json"
UNBLOCK_REQUESTS_FILE = "unblock_requests.json"
ATTEMPTS_FILE = "attempts.json"
AUTHORIZED_IPS_FILE = "authorized_ips.json"

def load_json(filename):
    if not os.path.exists(filename):
        return {}
    with open(filename) as f:
        return json.load(f)

def save_json(filename, data):
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)

@app.route("/unblock")
def unblock():
    token = request.args.get("token")
    if not token:
        return "Missing token", 400

    data = load_json(UNBLOCK_REQUESTS_FILE)
    requests = data.get("requests", [])

    for req in requests:
        if req["token"] == token:
            ip_to_unblock = req["ip"]

            # Remove IP from blacklist
            blacklist = load_json(BLACKLIST_FILE).get("ips", [])
            if ip_to_unblock in blacklist:
                blacklist.remove(ip_to_unblock)
                save_json(BLACKLIST_FILE, {"ips": blacklist})

            # Reset failed attempts
            attempts_data = load_json(ATTEMPTS_FILE)
            if ip_to_unblock in attempts_data:
                del attempts_data[ip_to_unblock]
                save_json(ATTEMPTS_FILE, attempts_data)

            # Remove token
            data["requests"] = [r for r in requests if r["token"] != token]
            save_json(UNBLOCK_REQUESTS_FILE, data)

            return f"IP {ip_to_unblock} has been unblocked successfully."

    return "Invalid or expired token", 404

@app.route("/approve_ip")
def approve_ip():
    ip = request.args.get("ip")
    username = request.args.get("username")
    if not ip or not username:
        return "Missing parameters", 400

    auth_ips = load_json(AUTHORIZED_IPS_FILE)
    user_ips = auth_ips.get(username, [])
    if ip not in user_ips:
        user_ips.append(ip)
        auth_ips[username] = user_ips
        save_json(AUTHORIZED_IPS_FILE, auth_ips)

    return f"IP {ip} has been approved for user {username}. You may now log in."

@app.route("/reject_ip")
def reject_ip():
    ip = request.args.get("ip")
    username = request.args.get("username")
    if not ip or not username:
        return "Missing parameters", 400

    blacklist = load_json(BLACKLIST_FILE).get("ips", [])
    if ip not in blacklist:
        blacklist.append(ip)
        save_json(BLACKLIST_FILE, {"ips": blacklist})

    return f"The login attempt from IP {ip} was blocked. Your account might have been compromised.\n\nPlease change your password immediately and review your security settings.\n\nSecurity Tips:\n- Use unique, strong passwords.\n- Don’t reuse passwords across platforms.\n- Avoid suspicious links.\n- Enable 2FA whenever possible."

if __name__ == "__main__":
    app.run(port=8000)
