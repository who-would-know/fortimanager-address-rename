FortiManager Address Object Rename Script
This script automates the process of logging into FortiManager, finding ADOMs based on FortiGate devices, and renaming address objects to include IP addresses.
Description
The script streamlines the process of managing address objects in FortiManager by:

    Logging into FortiManager
    Identifying ADOMs associated with specific FortiGate devices
    Renaming address objects to include IP addresses

Usage

    Option 1) Python Windows EXE file.
            Download EXE Program under /dist folder (Click on *.exe then click on View Raw Link to DL)
            Double click EXE file follow instructions

    Option 2) Run locally via python or create EXE via pyinstaller
            Clone the repository to your local machine (Windows if creating Windows EXE)
            pip install pyinstaller
            See 'Build python to exe HOWTO.txt' file for pyinstaller command
            run EXE file under created /dist

Requirements

    Python 3.10
    FortiManager API access with R/W API user account.
    FortiGate Device Name displayed in FortiManager
