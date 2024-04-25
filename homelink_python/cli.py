from homelink_python.client import HomeLinkClient

import os
import pathlib
import sys

class HomeLinkConfig:
    def __init__(self):
        self.hostId = ""
        self.serverAddress = ""
        self.serverControlPort = ""
        self.serverDataPort = ""

    def valid(self) -> bool:
        return (
            self.hostId
            and self.serverAddress
            and self.serverControlPort
            and self.serverDataPort
        )


def readConfig(configFilePath: str) -> HomeLinkConfig:
    config = HomeLinkConfig()

    with open(configFilePath, "r") as configFile:
        for line in configFile:
            tokens = line.split()
            if len(tokens) != 2:
                continue

            key, value = tokens

            if key == "host_id":
                config.hostId = value
            elif key == "server_address":
                config.serverAddress = value
            elif key == "server_control_port":
                config.serverControlPort = value
            elif key == "server_data_port":
                config.serverDataPort = value

    return config

def editConfig(args: list, configFilePath: str):
    config = readConfig(configFilePath)

    for arg in args:
        tokens = arg.split("=")
        if len(tokens) != 2:
            continue

        key, value = tokens

        if key == "--host-id":
            config.hostId = value
        elif key == "--server-address":
            config.serverAddress = value
        elif key == "--server-control-port":
            config.serverControlPort = value
        elif key == "--server-data-port":
            config.serverDataPort = value

    with open(configFilePath, "w") as configFile:
        if config.hostId:
            configFile.write(f"host_id {config.hostId}\n")
        if config.serverAddress:
            configFile.write(f"server_address {config.serverAddress}\n")
        if config.serverControlPort:
            configFile.write(f"server_control_port {config.serverControlPort}\n")
        if config.serverDataPort:
            configFile.write(f"server_data_port {config.serverDataPort}\n")

def handleCommand(serviceId: str, args: list):
    pass
        
def main():

    configFilePath = os.getenv("HOMELINK_PYTHON_CLI_CONFIG")
    if not configFilePath:
        homeDirectory = str(os.path.expanduser("~"))
        os.makedirs(homeDirectory + "/.config/homelink/", exist_ok=True)
        configFilePath = homeDirectory + "/.config/homelink/python_cli_config.conf"
        pathlib.Path(configFilePath).touch(0o777, exist_ok=True)
    
    if len(sys.argv) == 1:
        print("Need serviceId or --configure as first argument")
        return
    
    if sys.argv[1] == "--configure":
        editConfig(sys.argv[2:], configFilePath)
        return

    config = readConfig(configFilePath)
    if not config.valid():
        print("Incomplete config file!")
    
    handleCommand(sys.argv[1], sys.argv[2:])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
