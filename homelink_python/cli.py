from homelink_python.client import HomeLinkClient
from homelink_python.packet import LoginStatus

import os
import pathlib
import sys

class HomeLinkConfig:
    def __init__(self):
        self.hostId = ""
        self.serverAddress = ""
        self.serverPort = ""

    def valid(self) -> bool:
        return (
            self.hostId
            and self.serverAddress
            and self.serverPort
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
            elif key == "server_port":
                config.serverPort = value

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
        elif key == "--server-port":
            config.serverPort = value

    with open(configFilePath, "w") as configFile:
        if config.hostId:
            configFile.write(f"host_id {config.hostId}\n")
        if config.serverAddress:
            configFile.write(f"server_address {config.serverAddress}\n")
        if config.serverPort:
            configFile.write(f"server_port {config.serverPort}\n")

def handleCommand(client: HomeLinkClient, args: list):
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
    
    client = HomeLinkClient(config.hostId, sys.argv[1], config.serverAddress, int(config.serverPort))
    client.connect()
    status = client.login("hi")
    if status != LoginStatus.LOGIN_SUCCESS:
        print("Login failed")
        return
    handleCommand(client, sys.argv[2:])
    client.logout()
    client.destruct()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
