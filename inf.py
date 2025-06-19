import json
from datetime import datetime
from influxdb import InfluxDBClient

INFLUX_HOST = "localhost"
INFLUX_PORT = 8086
INFLUX_DB = "honeypot_logs"

client = InfluxDBClient(host=INFLUX_HOST, port=INFLUX_PORT)
client.switch_database(INFLUX_DB)

with open("normalized_logs.json", "r") as f:
    for line in f:
        try:
            log = json.loads(line.strip())

            # Convert ISO time to RFC3339 
            timestamp = log["timestamp"]

            json_body = [
                {
                    "measurement": "honeypot_events",
                    "tags": {
                        "honeypot": log.get("honeypot"),
                        "protocol": log.get("protocol"),
                        "attack_type": log.get("attack_type"),
                        "src_ip": log.get("src_ip"),
                    },
                    "time": timestamp,
                    "fields": {
                        "dest_port": int(log.get("dest_port", 0)),
                    },
                }
            ]

            client.write_points(json_body)
        except Exception as e:
            print(f" Error: {e}\nLine: {line.strip()}")
