from flask import Flask, render_template
import json
import os

app = Flask(__name__)

DATA_FILE = "packets.json"


@app.route("/")
def dashboard():

    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            packets = json.load(f)
    else:
        packets = []

    tcp = sum(1 for p in packets if p["protocol"] == "TCP")
    udp = sum(1 for p in packets if p["protocol"] == "UDP")
    icmp = sum(1 for p in packets if p["protocol"] == "ICMP")
    arp = sum(1 for p in packets if p["protocol"] == "ARP")

    stats = {
        "total": len(packets),
        "tcp": tcp,
        "udp": udp,
        "icmp": icmp,
        "arp": arp
    }

    packets.reverse()

    return render_template(
        "dashboard.html",
        packets=packets[:20],
        stats=stats
    )


if __name__ == "__main__":
    app.run(debug=True)