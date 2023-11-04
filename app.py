# Import the modules
import os
from flask import Flask, render_template, request, jsonify
import sqlite3
import pyshark

os.environ["TSHARK_PATH"] = "C:\\Program Files\\Wireshark"

# Create a Flask app
app = Flask(__name__, static_folder='static')


# Create or connect to an SQLite database
conn = sqlite3.connect("network_data.db")
c = conn.cursor()

# Define a table schema
c.execute('''
    CREATE TABLE IF NOT EXISTS network_packets (
        source_ip TEXT,
        destination_ip TEXT,
        protocol TEXT,
        length INTEGER
    )
''')

# Commit changes
conn.commit()

# Open the captured PCAP file
cap = pyshark.FileCapture("sample2.cpap.pcapng")

# Loop through the captured packets and insert data into the database
for packet in cap:
    if "IP" in packet:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        proto = packet.transport_layer
        length = int(packet.length)

        # Insert data into the database
        c.execute("INSERT INTO network_packets (source_ip, destination_ip, protocol, length) VALUES (?, ?, ?, ?)",
                  (src_ip, dst_ip, proto, length))

# Commit changes and close the database connection
conn.commit()
conn.close()

# Define a route for the home page
@app.route("/")
def index():
    return render_template("index.html")

# Update the API route
@app.route("/api")
def api():
    # Get the query parameters
    src = request.args.get("src")
    dst = request.args.get("dst")
    proto = request.args.get("proto")
    length = request.args.get("len")
    port = request.args.get("port")

    # Create a database connection
    conn = sqlite3.connect("network_data.db")
    c = conn.cursor()

    # Build a SQL query based on the parameters
    query = "SELECT * FROM network_packets WHERE 1=1"
    params = []

    # Modify the source_ip parameter to perform a partial match
    if src:
        # Use the LIKE operator with the '%' wildcard
        query += " AND source_ip = ?"
        params.append(src)
    if dst:
        query += " AND destination_ip = ?"
        params.append(dst)
    if proto:
        query += " AND protocol = ?"
        params.append(proto)
    if length:
        query += " AND length = ?"
        params.append(length)
    if port:
        query += " AND port = ?"
        params.append(port)

    # Execute the query and fetch the results
    c.execute(query, params)
    results = c.fetchall()

    # Close the connection
    conn.close()

    # Return the results as JSON
    return ({"results": results})



# Run the app
if __name__ == "__main__":
    app.run(debug=True)