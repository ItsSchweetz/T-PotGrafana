import json
import glob

normalized_logs = []

def normalize_cowrie(log):
    return {
        "timestamp": log.get("timestamp"),
        "src_ip": log.get("src_ip"),
        "dest_port": log.get("dst_port", 22),
        "protocol": log.get("protocol", "ssh"),
        "attack_type": "connection",
        "honeypot": "cowrie",
        "raw": log
    }

def normalize_dionaea(log):
    return {
        "timestamp": log.get("timestamp"),
        "src_ip": log.get("src_ip"),
        "dest_port": log.get("dst_port"),
        "protocol": log.get("connection", {}).get("protocol", "unknown"),
        "attack_type": "malware_attempt",
        "honeypot": "dionaea",
        "raw": log
    }

def normalize_h0neytr4p(log):
    return {
        "timestamp": log.get("timestamp"),
        "src_ip": log.get("src_ip"),
        "dest_port": log.get("dest_port"),
        "protocol": log.get("protocol"),
        "attack_type": log.get("request_method"),
        "honeypot": "h0neytr4p",
        "raw": log
    }

def normalize_elasticpot(log):
    return {
        "timestamp": log.get("timestamp"),
        "src_ip": log.get("src_ip"),
        "dest_port": log.get("dst_port"),
        "protocol": "http",
        "attack_type": log.get("message", "exploit_attempt"),
        "honeypot": "elasticpot",
        "raw": log
    }

def normalize_mailoney(log):
    return {
        "timestamp": log.get("timestamp"),
        "src_ip": log.get("src_ip"),
        "dest_port": 25,
        "protocol": "smtp",
        "attack_type": "spam_or_probe",
        "honeypot": "mailoney",
        "raw": log
    }

# Load and normalize logs
for filepath in glob.glob("cowrie.json.*"):
    with open(filepath) as f:
        for line in f:
            log = json.loads(line)
            normalized_logs.append(normalize_cowrie(log))

for filepath in glob.glob("dionaea.json.*"):
    with open(filepath) as f:
        for line in f:
            log = json.loads(line)
            normalized_logs.append(normalize_dionaea(log))

for filepath in glob.glob("log.json.*"):
    with open(filepath) as f:
        for line in f:
            log = json.loads(line)
            normalized_logs.append(normalize_h0neytr4p(log))

for filepath in glob.glob("elasticpot.json.*"):
    with open(filepath) as f:
        for line in f:
            log = json.loads(line)
            normalized_logs.append(normalize_elasticpot(log))

for filepath in glob.glob("mail.log.*"):
    with open(filepath) as f:
        for line in f:
            log = json.loads(line)
            normalized_logs.append(normalize_mailoney(log))

#output
with open("normalized_logs.json", "w") as f:
    for entry in normalized_logs:
        f.write(json.dumps(entry) + "\n")
