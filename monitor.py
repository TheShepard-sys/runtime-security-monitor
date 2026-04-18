import psutil
import time
import logging

logging.basicConfig(
    filename="logs/security.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

SUSPICIOUS_NAMES = ["miner", "crypto", "hack", "malware"]
CPU_THRESHOLD = 80
MEM_THRESHOLD = 80

def check_processes():
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            name = proc.info['name'].lower()
            cpu = proc.info['cpu_percent']
            mem = proc.info['memory_percent']

            if any(word in name for word in SUSPICIOUS_NAMES):
                print(f"[ALERT] Suspicious process: {name}")
                logging.warning(f"Suspicious process detected: {name}")

            if cpu > CPU_THRESHOLD:
                print(f"[WARNING] High CPU: {name} ({cpu}%)")
                logging.warning(f"High CPU usage: {name} ({cpu}%)")

            if mem > MEM_THRESHOLD:
                print(f"[WARNING] High Memory: {name} ({mem}%)")
                logging.warning(f"High Memory usage: {name} ({mem}%)")

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

def main():
    print("Runtime Security Monitor started...")
    while True:
        check_processes()
        time.sleep(5)

if __name__ == "__main__":
    main()
