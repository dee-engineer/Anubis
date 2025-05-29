from collections import defaultdict
from time import time

connection_attempts = defaultdict(list)
RATE_LIMIT = 5  # Max connections per minute
RATE_LIMIT_WINDOW = 60  # Seconds

def is_rate_limited(ip):
    current_time = time()
    connection_attempts[ip] = [t for t in connection_attempts[ip] if current_time - t < RATE_LIMIT_WINDOW]
    if len(connection_attempts[ip]) >= RATE_LIMIT:
        return True
    connection_attempts[ip].append(current_time)
    return False