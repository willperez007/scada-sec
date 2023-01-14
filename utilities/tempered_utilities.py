#willperez007 Tempered Sample Script

from ipaddress import ip_address
import json
from multiping import MultiPing
import os
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import sys
import time
import base64

# Suppress cert warning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


http_proxy = "http://localhost:8080"
https_proxy = "https://localhost:8080"


proxyDict = {
    "http" : http_proxy,
    "https" : https_proxy

}

tempered_host = ""
url = "https://" + tempered_host + "/api/v1/"

#Authentication provider local or ldap
provider = "local"

client_id = ""
api_token = ""

headers = {
    'x-api-client-id': client_id,
    'x-api-token': api_token,
    'content-type': 'application/json'
}


def get_token():
    """
    Get an API token - WP

    Response Body
    {
        "client_id": "",
        "token": ""
    }

    """

    r = requests.post(url + "auth" + provider, headers=headers, verify=False)

    if r.status_code == requests.codes.ok:
        return r.json()
    else:
        print('Error getting token')
        print(r.json())
        sys.exit()

def generate_menu_select(cont, msg):
    """
    Generate a menu structure from a list of dictionaries

    :param cont: content to be processed
    :param msg: message to be asked

    :returns: selected object from list
    """

    data = sorted(cont, key=lambda k: k['name'])
    for d in data:

        print('{0}) {1}'.format(data.index(d) + 1, d['name']))

    i = input(msg)

    try:
        return(data[int(i) - 1])
    except (IndexError, ValueError):
        print('Selected input {0} not found or invalid'.format(i))
        sys.exit()

def print_json(cont):
    """
    Generate a menu structure from a list of dictionaries

    :param cont: content to be processed

    :returns: selected object from list
    """

    data = sorted(cont, key=lambda k: k['name'])
    for d in data:
        print('{0}) {1} : {2}'.format(data.index(d) + 1, d['name'], d['description']))



def get_overlay():
    """
    Get all overlays in Conductor

    :returns: selected overlay network
    """

    r = requests.get(url + "overlay_networks", headers=headers, proxies=proxyDict,verify=False)

    if r.status_code == requests.codes.ok:
        #print('Collected overlays:')
        return (r.json())
        #return generate_menu_select(r.json(),
         #                           "Select overlay network to failover: ")
    else:
        print('Error getting overlay networks')
        print(r.json())
        sys.exit()


def get_object_in_overlay(devs, dgs, ovl_gps):
    """
    Get all devices/device groups in the overlay. Move to own list.

    :param devs: all devices
    :param dgs: all device groups
    :param ovl_gps: all devices/device groups in overlay

    :returns: selected device/device group
    """

    # devices and device groups
    grps = [d for d in devs for o in ovl_gps if o == d['uuid']]
    grps.extend([d for d in dgs for o in ovl_gps if o == d['uuid']])

    print('Collected devices and device groups in overlay network:')
    return generate_menu_select(grps, 'Select device/device group to replace: ')


def get_device_groups():
    """
    Get all device groups in Conductor

    :returns: all Conductor device groups
    """

    r = requests.get(url + "device_groups", headers=headers, verify=False)

    if r.status_code == requests.codes.ok:
        return r.json()
    else:
        print('Error getting device groups')
        print(r.json())
        sys.exit()


def get_devices():
    """
        Get all devices in Conductor

        :returns: all Conductor devices
        """

    r = requests.get(url + "devices", headers=headers, proxies=proxyDict, verify=False)

    if r.status_code == requests.codes.ok:
        return r.json()
    else:
        print('Error getting devices')
        print(r.json())
        sys.exit()


def get_device(d_uuid):
    """
    Get a device in the Conductor
    :param d_uuid: device UUID


    :returns: all Conductor devices
    """

    payload = {'id': [d_uuid]}


    r = requests.get(url + "devices/" + d_uuid, headers=headers, proxies=proxyDict, data=json.dumps(payload),verify=False)


    if r.status_code == requests.codes.ok:
        print_json(r)
        return r.json()

    else:
        print('Error getting device:' + d_uuid)
        print(r.json())
        sys.exit()

def export_devices():
    """
    Get all devices in Conductor and export in CSV format

    :returns: all Conductor devices
    """

    r = requests.get(url + "export_devices", headers=headers, verify=False)

    if r.status_code == requests.codes.ok:
        return r.json()
    else:
        print('Error getting devices')
        print(r.json())
        sys.exit()

def get_hipservices ():
    """
        Get all hipservices in Conductor

        :returns: all hipservices
        """

    r = requests.get(url + "hipservices", headers=headers, verify=False)

    if r.status_code == requests.codes.ok:
        return r.json()
    else:
        print('Error getting hipservices')
        print(r.json())
        sys.exit()


def get_hipservices_linkstate(d_uuid):

    print ("u_uuid:" + d_uuid)
    r = requests.get(url + "hipservices/"+d_uuid+"/traffic_stats", headers=headers, verify=False)

    if r.status_code == requests.codes.ok:
        return r.json()
    else:
        print('Error getting hipservices')
        print(r.json())
        sys.exit()

def add_device_to_overlay(ovl_uuid, d_uuid):
    """
    Add a device to an overlay network

    :param ovl_uuid: overlay network UUID
    :param d_uuid: device UUID
    """

    payload = {'network_id': ovl_uuid,
               'device_group_ids': [d_uuid]}

    r = requests.post(url + "overlay_network_devices", headers=headers,
                      data=json.dumps(payload), verify=False)

    if not r.status_code == requests.codes.ok:
        print('Error adding to overlay')
        print(r.json())
        sys.exit()


def remove_device_from_overlay(ovl_uuid, d_uuid):
    """
    Remove a device from an overlay network

    :param ovl_uuid: overlay network UUID
    :param d_uuid: device UUID
    """

    payload = {'network_id': ovl_uuid,
               'device_group_ids': [d_uuid]}

    r = requests.delete(url + "overlay_network_devices", headers=headers,
                        data=json.dumps(payload), verify=False)

    if not r.status_code == requests.codes.ok:
        print('Error removing from overlay')
        print(r.json())
        sys.exit()


def build_overlay_policy(ovl_uuid, d_uuid, ds_uuid):
    """
    Build the overlay policy

    :param ovl_uuid: overlay network UUID
    :param d_uuid: device UUID
    :param ds_uuid: UUIDs of devices in policy with previous device (target)
    """

    for uuid in ds_uuid:
        payload = {'network_id': ovl_uuid,
                   'device_group_1': d_uuid,
                   'device_group_2': uuid}

        r = requests.post(url + "overlay_network_devices/trust", headers=headers,
                          data=json.dumps(payload), verify=False)

        if not r.status_code == requests.codes.ok:
            print('Error adding policy in overlay')
            print(r.json())


def get_replacement_object(devs, dgs):
    """
    Select which object to use as a replacement

    :param devs: all devices
    :param dgs: all device groups

    :returns: device/device group JSON data
    """

    selection = [{'name': 'Device'}, {'name': 'Device Group'}]

    sel = generate_menu_select(selection, 'Type to replace with: ')

    if sel['name'] == 'Device':
        return generate_menu_select(devs, 'Select replacement device: ')
    elif sel['name'] == 'Device Group':
        return generate_menu_select(dgs, 'Select replacement device group: ')


def replace_overlay_object(ovl, target, replacement):
    """
    Replace a given target with a replacement device/device group object

    :param ovl: overlay JSON data
    :param target: target device JSON data
    :param replacement: replacement device JSON data
    """

    policies = [p for p in [t['from'] for t in ovl['policy'] if t['to'] == target['uuid']]]

    remove_device_from_overlay(ovl['uuid'], target['uuid'])
    print('Removing device from overlay')
    add_device_to_overlay(ovl['uuid'], replacement['uuid'])
    print('Adding replacement device to overlay')
    build_overlay_policy(ovl['uuid'], replacement['uuid'], policies)
    print('Build overlay policy with replacement device')


def select_mon_target():
    """
    Input an IP to monitor

    :returns: IP address to monitor
    """

    selection = True
    mon_target = None

    while selection:
        mon_target = input('Enter IP target to monitor: ')
        try:
            ip_address(mon_target)
            selection = False
        except ValueError:
            print('Invalid IP address.')
            continue

    return mon_target


def monitor_target(mon_target):
    """
    Monitor the given target import ip

    :param mon_target: IP address to monitor
    """

    active = True
    while active:
        if mon_target:
            mp = MultiPing([mon_target])
            mp.send()
            resp, no_resp = mp.receive(.1)
            stamp = time.strftime('%Y-%m-%d %H:%M:%S')

            if no_resp:
                print('{0}: Monitor failed'.format(stamp))
                break
            else:
                print('{0}: Ping monitor successful'.format(stamp))
                time.sleep(1)


def main():

    #if not os.geteuid() == 0:

       #print('Must run as root or Administrator. Exiting...')

    #else:



        #Custom calls to programs

        #print(get_devices())
        #print(export_devices)

        #Example of retrieving one device
        print(get_device("1e7eb7d1-2c9d-4efc-bd47-6bb02cf63570"))
        #response = get_device("1e7eb7d1-2c9d-4efc-bd47-6bb02cf63570")
        #print_json(json.loads(response))
        #d_uuid = dev['uuid']
        #get_hipservices_linkstate("49e5de22-ce4e-440f-90d7-d9408cf3a272")

        #print(get_hipservices())

        # get content
        #ovl = get_overlay()
        #print_json(ovl)
        #print ovl

        #dgs = get_device_groups()

        # ask questions
        #target = get_object_in_overlay(devs, dgs, ovl['device_groups'])
        #replacement = get_replacement_object(devs, dgs)

        # monitor ip
        #mon_target = select_mon_target()
        #monitor_target(mon_target)

        # do work
        #replace_overlay_object(ovl, target, replacement)
        #print('Device failover completed')


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()
