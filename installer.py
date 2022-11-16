import platform
import os
import sys

def main():
    sysx = platform.system()
    if sysx == "Windows":
        print("Detected OS: Windows, nothing to install here.")
    if sysx == "Linux":
        print("Detected OS: Linux, trying to install dependencys.")
        print("Note: Run this script with sudo-privileged.")
        os.system("apt-get update")
        os.system("apt-get install traceroute")
        os.system("apt-get install net-utils")
        os.system("apt-get install iproute*")
        os.system("apt-get install net-tools")
        os.system("apt-get install netstat")



if __name__ == '__main__':
    main()
