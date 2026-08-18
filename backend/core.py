import json
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))

from tools.memory import get_memory
from tools.cpu import read_cpu
from tools.disk import get_disk
from tools.processes import get_processes
from tools.network import get_network_info
from tools.services import get_services
from tools.logs import get_logs


def collect_system_info():

    return {
        "memory": get_memory(),
        "cpu": read_cpu(),
        "disk": get_disk(),
        "processes": get_processes(),
        "network": get_network_info(),
        "services": get_services(),
        "logs": get_logs()
    }


if __name__ == "__main__":

    data = collect_system_info()

    print(
        json.dumps(
            data,
            indent=2
        )
    )
