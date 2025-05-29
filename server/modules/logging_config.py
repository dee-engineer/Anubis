import logging
import os

def setup_logging():
    if not os.path.exists('logs'):
        os.makedirs('logs')
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - Session %(session_id)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/server.log'),
            logging.StreamHandler()
        ]
    )