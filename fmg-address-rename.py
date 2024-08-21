#!/usr/bin/python

import os
import os.path
import sys
import time
import requests
import urllib3
# Ignore Self Signed Certs from Devices
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()
import json
import getpass
# Module file for logging outputs
import transcript
# Converting IP Subnet mask
import ipaddress
# Regex find IP
import re

### Define additional global variables
taskID = ''
# Default User Input values
default_hostIP = '192.168.1.1'
default_hostADMIN = 'script_user'
default_hostPASSWD = 'pass'
default_fgtDEVname = 'fwcluster-fw03'

### Start Logging
# Remove previous log files and create a new files
if os.path.isfile('mainLOG.txt'):
    os.remove('mainLOG.txt')
if os.path.isfile('ERRORlog.txt'):
        os.remove('ERRORlog.txt')
transcript.start('mainLOG.txt')
ERRORlog = open("ERRORlog.txt", "a")
print ('>> Start logging script output to mainLOG.txt <<')
# Start stopwatch for script timing
stopwatchSTART = time.time()

### FUNCTIONS
def continue_script():
    print ('-=-' * 20)
    while True:
        try:
            print('--> Continue script with current variables? (y or n): ')
            goNOgo = input()
        except ValueError:
            print ('    Input not understood, please input y or n.')
            continue
        if goNOgo == 'y':
            print ('    Variables accepted, continuing script.')
            print
            print ('-=-' * 20)
            print
            goNOgo = ''
            break
        elif goNOgo == 'n':
            print ('    Variables NOT accepted, exiting script!')
            print
            exit()
        else:
            print ('    Input not understood, please input y or n!')
            print
            continue

def pretty_print_json(jsonLIST):
    for json_obj in jsonLIST:
        print(json.dumps(json_obj, indent=2))

def subnet_mask_to_cidr(subnet_mask):
    # Convert the subnet mask to an integer
    mask_int = sum([bin(int(x)).count('1') for x in subnet_mask.split('.')])
    # Return the CIDR notation
    return '/' + str(mask_int)

def fmg_login(hostAPIUSER, hostPASSWD, hostIP):
    '''FortiManager Login & Create Session
    Arguments:
    hostAPIUSER - API User Account Name
    hostPASSWD - API User Passwd
    hostIP - IP addres of FortiManager. Note, if not on default HTTPS(443) port can input: 1.1.1.1:8080
    '''
    # Global Save Session ID
    global session
    # Create HTTPS URL
    global url
    url = 'https://' + hostIP + '/jsonrpc'
    # JSON Body to sent to API request
    body = {
    "id": 1,
            "method": "exec",
            "params": [{
                    "url": "sys/login/user",
                    "data": [{
                            "user": hostAPIUSER,
                            "passwd": hostPASSWD
                    }]
            }],
            "session": 1
    }
    # Test HTTPS connection to host then Capture and output any errors
    try:
        r = requests.post(url, json=body, verify=False)
    except requests.exceptions.RequestException as e: 
        print (SystemError(e))
        # Exit Program, Connection was not Successful
        sys.exit(1)
    # Save JSON response from FortiManager
    json_resp = json.loads(r.text)
    # Check if User & Passwd was valid, no code -11 means invalid
    if json_resp['result'][0]['status']['code'] != -11:
        session = json_resp['session']
        print ('--> Logging into FortiManager: %s' % hostIP)
        # HTTP & JSON code & message
        print ('<-- HTTPcode: %d JSONmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
        print
    else:
        print ('<--Username or password is not valid, please try again, exiting...')
        # HTTP & JSON code & message
        print ('<-- HTTPcode: %d JSONmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
        print
        # Exit Program, Username or Password is not valided or internal FortiManager error review Hcode & Jmesg
        sys.exit(1)

def fmg_logout(hostIP):
    '''FortiManager logout
    Arguments:
    hostIP - IP addres of FortiManager. Note, if not on default HTTPS(443) port can input: 1.1.1.1:8080
    '''
    body = {
       "id": 1,
        "method": "exec",
        "params": [{
                "url": "sys/logout"
        }],
        "session": session
    }
    # Test HTTPS connection to host then Capture and output any errors
    try:
        r = requests.post(url, json=body, verify=False)
    except requests.exceptions.RequestException as e:
        print (SystemError(e))
        # Exit Program, Connection was not Successful
        sys.exit(1)
    # Save JSON response from FortiManager    
    json_resp = json.loads(r.text)
    # Check if any API Errors returned
    if json_resp['result'][0]['status']['code'] != -11:    
        print ('--> Logging out of FMG: %s' % hostIP)
        # HTTP & JSON code & message
        print ('<-- HTTPcode: %d JSONmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
        print
    else:
        print ('<--Error Occured, check Hcode & Jmesg')
        # Exit Program, internal FortiManager error review Hcode & Jmesg
        print ('<-- HTTPcode: %d JSONmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
        print
        sys.exit(1)   

### Get Adoms based off FortiGate Device
def get_adom(fgtDEVname):
        global adomLIST
        adomLIST = []
        json_url = "dvmdb/adom"
        body = {
                "id": 1,
                "method": "get",
                "params": [{
                        "expand member": [
                            {
                                "fields": [
                                    "name",
                                ],
                                "filter": [
                                    "name", "==", fgtDEVname
                                ],
                                "url": "/device"
                            }
                        ],
                       "fields": [
                            "name",
                       ],
                       "url": json_url
                }],
                "session": session,
                #"verbose": 1
        }
        r = requests.post(url, json=body, verify=False)
        json_resp = json.loads(r.text)
        #print(json.dumps(json_resp, indent=2))
        for entry in json_resp['result'][0]['data']:
            #print(entry);
            if "expand member" in entry:
                adomLIST.append(entry['name'])
                # print(entry)


def workspace_lock(lADOM):
    json_url = "pm/config/adom/" + lADOM + "/_workspace/lock"
    body = {
        "id": 1,
        "method": "exec",
        "params": [{
            "url": json_url
        }],
        "session": session
    }
    r = requests.post(url, json=body, verify=False)
    json_resp = json.loads(r.text)
    print ('--> Locking ADOM: %s' % lADOM)
    print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
    if 'No permission for the resource' in json_resp['result'][0]['status']['message']:
        print(f"<--!!!ERROR!!! Unable to lock for r/w to ADOM: {lADOM}. Check to make sure it's unlocked")
        print ("\n")
        ERRORlog.write(f"<-- !!!ERROR!!! Unable to lock for r/w to ADOM: {lADOM}. Check to make sure it's unlocked")
        return False
    return True

def workspace_commit(cADOM):
    json_url = "pm/config/adom/" + cADOM + "/_workspace/commit"
    body = {
        "id": 1,
        "method": "exec",
        "params": [{
            "url": json_url
        }],
        "session": session
    }
    r = requests.post(url, json=body, verify=False)
    json_resp = json.loads(r.text)
    print("\n")
    print ('--> Saving changes for ADOM %s' % cADOM)
    print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
    print ("\n")

def workspace_unlock(uADOM):
    json_url = "pm/config/adom/" + uADOM + "/_workspace/unlock"
    body = {
        "id": 1,
        "method": "exec",
        "params": [{
            "url": json_url
        }],
        "session": session
    }
    r = requests.post(url, json=body, verify=False)
    json_resp = json.loads(r.text)
    print ('--> Unlocking ADOM %s' % uADOM)
    print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
    print ("\n")

def status_taskid():
    global state
    json_url = "/task/task/" + str(taskID)
    body = {
        "id": 1,
        "method": "get",
        "params": [{
            "url": json_url
        }],
        "session": session
    }
    r = requests.post(url, json=body, verify=False)
    json_resp = json.loads(r.text)
    print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
    print
    #print json_resp['result']['data']['state']
    state = json_resp['result'][0]['data']['state']
    totalPercent = json_resp['result'][0]['data']['tot_percent']
    if state == 0:
        print ('    Current task state (%d): pending' % state)
    if state == 1:
        print ('    Current task state (%d): running' % state)
    if state == 2:
        print ('    Current task state (%d): cancelling' % state)
    if state == 3:
        print ('    Current task state (%d): cancelled' % state)
    if state == 4:
        print ('    Current task state (%d): done' % state)
    if state == 5:
        print ('    Current task state (%d): error' % state)
    if state == 6:
        print ('    Current task state (%d): aborting' % state)
    if state == 7:
        print ('    Current task state (%d): aborted' % state)
    if state == 8:
        print ('    Current task state (%d): warning' % state)
    if state == 9:
        print ('    Current task state (%d): to_continue' % state)
    if state == 10:
        print ('    Current task state (%d): unknown' % state)
    if json_resp['result'][0]['status']['message'] == 'OK':
        print ('    Current task percentage: (%d)' % totalPercent)
        print

def poll_taskid ():
    global state
    state = 0
    while state not in [3,4,5,7]:
        print ('--> Polling task: %s' % taskID)
        time.sleep( 3 )
        status_taskid()
    if state == 4:
        print ('--> Task %s is done!' % taskID)
        print
    else:
        print ('--> Task %s is DIRTY, check FMG task manager for details!' % taskID)
        print ('    Adding this ADOM to the error log %s !' % ERRORlog.name)
        ERRORlog.write("%s %s %s\n" % (fmgADOM, taskID, state))
        print

def create_adomrev(fmgADOM, hostADMIN):
    json_url = "dvmdb/adom/" + fmgADOM + "/revision"
    body = {
        "id": 1,
        "method": "add",
        "params": [{
            "url": json_url,
            "data": {
                "locked": 0,
                "desc": "Created via JSON API",
                "name": "Post ADOM DB upgrade",
                "created_by": hostADMIN
            }
        }],
        "session": session
    }
    r = requests.post(url, json=body, verify=False)
    json_resp = json.loads(r.text)
    print ('--> Creating ADOM revision')
    print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
    print
    time.sleep( 2 )

# Get Address Objects
def get_address(adom):
    json_url = "pm/config/adom/" + adom + "/obj/firewall/address"
    body = {
    "id": 1,
        "method": "get",
        "params":[  {
               "url": json_url,
        }],
        "session": session
    }
    
    r = requests.post(url, json=body, verify=False)
    json_resp = json.loads(r.text)
    #print (json.dumps(json_resp, indent=2))
    addrEXEMPT = ['all','FABRIC_DEVICE','FIREWALL_AUTH_PORTAL_ADDRESS','metadata-server', 'none' ]
    pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}\b"
    addrLIST = []
    for entry in json_resp['result'][0]['data']:
        if 'subnet' in entry:
            if entry['name'] not in addrEXEMPT:
                if not re.search(pattern,entry['name']):
                    addrLIST.append(entry)
    return addrLIST

# Update Address to <name>-<ip/mask>
def update_address(adom, addrLIST):
    newADDRESSNAME = []
    origADDRESSNAME = []

    for entry in addrLIST:
        newADDRESSNAME.append(entry['name'] + "-" + entry['subnet'][0] + subnet_mask_to_cidr(entry['subnet'][1]))
        origADDRESSNAME.append(entry['name'])
    # LOCK ADOM
    succLOCK = workspace_lock(adom)
    if succLOCK:
        for myaddr, mynewaddr in zip(origADDRESSNAME, newADDRESSNAME):
            json_url = "pm/config/adom/" + adom + "/obj/firewall/address/" + myaddr
            body = {
                "id": 1,
                "method": "update",
                "params":[  {
                    "data": {
                        "name": mynewaddr
                    },
                    "url": json_url,
                }],
                "session": session
            }
            r = requests.post(url, json=body, verify=False)
            json_resp = json.loads(r.text)
            print(f"--> Updating Address {myaddr} to {mynewaddr}")
            print(f"<-- Hcode: {r.status_code} Jmesg: {json_resp['result'][0]['status']['message']}")
            time.sleep( 0.3 )
        # SAVE ADOM
        workspace_commit(adom)
        # Unlock ADOM
        workspace_unlock(adom)
    
##########
#### MAIN
##########

# Main section
def main():
    ### Warning message
    print ('\n==DISCLAIMER==\nThis script will be doing the following: \n Looking for Address Objects that do not include their IP address then renaming them. \n ex. LAN_NET => LAN_NET-192.168.1.0/24 \nThis script will ask for the FortiGate Cluster then find all ADOM associated to update. \n\nIt is the responsibility of the user to verify via FortiManager => Task Monitor changes done.\nLog files will be created for viewing when completed "mainLOG.txt", ERRORlog.txt".\n====')
    print ('!!! Please make sure a FortiManager Backup and/or Snapshot(vm) before running script.Thanks!!!!\n==\n')

    ### Get variables from user input
    print ('--> Prompting for variables to use \n--> Please provide values or except defaults\n')

    ### Get FortiManager Info
    print ('================FMG=============')
    print(f'FortiManager IP address? (default: {default_hostIP}): ')
    hostIP = input()
    if hostIP == '':
        hostIP = default_hostIP
    print ('    Using: %s' % hostIP)

    print(f'FortiManager API admin (Read/Write required)? (default: {default_hostADMIN}): ')
    hostADMIN = input()
    if hostADMIN == '':
        hostADMIN = default_hostADMIN
    print ('    Using: %s' % hostADMIN)

    hostPASSWD = getpass.getpass('FortiManager API password? (default: ---): ')
    if hostPASSWD == '':
        hostPASSWD = default_hostPASSWD
    hostPASSWDlength = (len(hostPASSWD))
    secret = '*' * hostPASSWDlength
    print ('    Using: %s' % secret)

    print(f'FortiGate device name as seen in FMG device mgr tab? (default: {default_fgtDEVname}): ')
    fgtDEVname = input()
    if fgtDEVname == '':
        fgtDEVname = default_fgtDEVname
    print ('    Using: %s' % fgtDEVname)
    # Check with user on above input before starting
    continue_script()
        
    ### Log into FMG
    print
    print ('-=-' * 20)
    print ('Logging into FMG %s' % hostIP)
    print ('-=-' * 20)
    print
    ### FMG Login
    fmg_login(hostADMIN, hostPASSWD, hostIP)

    # Get ADOM list based on FortiGate Device
    get_adom(fgtDEVname)
    print ("\n")
    print(f"<-- Found following ADOM(s) for FortiGate Device {fgtDEVname}:") 
    for myadom in adomLIST:
        print(myadom)
    continue_script()

    # Get addresses, update addresses, main function logic
    addressNAMELIST = []
    for myadom in adomLIST:
        print(f"<-- Checking ADOM: {myadom} for Address Objects that need formatting.")
        addressNAMELIST = get_address(myadom)
        if addressNAMELIST:
            update_address(myadom, addressNAMELIST)
        else:
            print(f"<--!!! No Address Object needing formatting found in ADOM: {myadom} \n")
            
    ## Logout
    fmg_logout(hostIP)

    ## Exit Program, save Log file, keep Terminal Window Open for Customer experience with EXE
    print ('-=-' * 20)
    stopwatchTOTAL = time.time()-stopwatchSTART
    print ('>>>>>> %s ran for %d seconds <<<<<<' % (sys.argv[0], stopwatchTOTAL))
    print ('-=-' * 20)

    print ('>> Stop logging script output to mainLOG.txt <<')
    ERRORlog.close()
    transcript.stop()
    print ('-=-' * 20)
    print ('Completed Script, for Log files please view "mainLOG.txt" and "ERRORlog.txt" .\n')
    print ('Closing console in 5..4..3..2..1.')
    time.sleep( 5 )

####Run MAIN FUNCTION
if __name__ == "__main__":
    main()

######
### EOF
######