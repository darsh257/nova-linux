import json

from backend.tools.memory import get_memory
from backend.tools.cpu import read_cpu
from backend.tools.disk import get_disk
from backend.tools.processes import get_processes
from backend.tools.network import get_network_info
from backend.tools.services import get_services
from backend.tools.logs import get_logs


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
