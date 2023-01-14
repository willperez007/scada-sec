#willperez007 Cylance Utility
#!/usr/bin/python3

#from ipaddress import ip_address
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

#base64 decoding of username and password
username = base64.standard_b64decode("").strip()
password = base64.standard_b64decode("").strip()

http_proxy = "http://localhost:8080"
https_proxy = "https://localhost:8080"

proxyDict = {
    "http" : http_proxy,
    "https" : https_proxy

}

credentials = {
    "username":username,
    "password":password

}

#Snipe IT Code
snipe_it_access_token = ""

def get_hardware():
        URL = "https://assetmanagement.snipe-it.io/api/v1/hardware"
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application / json",
            "Authorization": "Bearer " + snipe_it_access_token
        }

        params = {
            "search": "icsp",
            "limit": "10000"
        }
        print(headers)
        resp = requests.get(URL, headers=headers, json=params, proxies=proxyDict, verify=False)

        if resp.status_code == requests.codes.ok:
            # return json.loads(resp.text)['access_token']
            return resp
        else:
            print('Error getting URL:' + url)
            print(resp.content())

#url = "https://"
#url = "https://"

headers = {
    'User-Agent':'application/python'
}

def get_system_cpuusage(cookie,ip):
    """
    Get System CPU Usage

    """
    r = requests.get("https://" + ip + "/api/system/getcpuusage", headers=headers, proxies=proxyDict, cookies=cookie ,verify=False)
    #print (r.content)
    #print (r.json['result'])
    #print (r.headers)

    if r.status_code == requests.codes.ok:
        return r
    else:
        print('Error making api call')
        print(r.json())
        sys.exit()

def get_malwarelogmultiple(cookie,ip):
    """
    Get Malware Log Report (Only shows infections detected not number of files cleaned.

    """

    params = {
        "method": "Scada.getMalwareLogMultiple",
        "start": "2022-01-10",
        "amount": 100,
        "end": "2022-04-09"
    }



    r = requests.post("https://" + ip + "/api/scada/getMalwareLogMultiple", json=params, proxies=proxyDict, cookies=cookie ,verify=False)


#    for results in r['result']:
#        for malware_name in r['malware_name']:
#                    print r['malware_name']


    if r.status_code == requests.codes.ok:
        return r.json()
    else:
        print('Error making api call')
        print(r.status_code)
        sys.exit()

def get_scanlogmultiple(cookie,ip):
    """
    Get Scan Log Report.

    """
    params = {
        "method": "Scada.getScanLogMultiple",
        "start": "2019-01-01",
        "amount": 100,
        "end": "2019-04-09"
    }


    r = requests.post("https://" + ip + "/api/scada/getMalwareLogMultiple", headers=headers, json=params, proxies=proxyDict, cookies=cookie ,verify=False)
    #print (r.json['result'])
    #print (r.headers)

    if r.status_code == requests.codes.ok:
        return r.json()
    else:
        print('Error making api call')
        print(r.status_code)
        sys.exit()

def print_json(data):
    """

    :param data: data to be processed

    :returns: selected object from list
    """

    #data = sorted(data, key=lambda k: k[1])
    for element in data:
        #print('{0} : {1}'.format(d['action_value'], d['qtn_filename']))
    #print (data['result'])
        print (element["action_value"])

def get_auth_session(ip):
    """
    Get Auth Session cookie for further API calls

    """

    r = requests.post("https://" + ip + "/auth", headers=headers, proxies=proxyDict, params = credentials, verify=False)
    print (r.content)
    #print (r.json['result'])
    #print (r.headers)

    print("this is in get_auth_session https status code: ", r.status_code)
    if r.status_code == 200:
        return r
    elif r.status_code == 401:
        print("Credentials failed:" , credentials)
        sys.exit()
    else:
        print('Error making api call')
        #print(r.json())
        sys.exit()

def main():

   # if not os.geteuid() == 0:
    #    print('Must run as root or Administrator. Exiting...')

    #else:

   #Call Snipe-IP function and retrieve ICSP IP addresses
   response = get_hardware()
   #+print(response.text)
   data = response.json()

   # Parsing the get_devices function API response
   # Iterate each of the JSON records.  "page_items" is the first structure that you can iterate
   # Used when identifying the json fields to parse
   # print('keys in json:', data.keys())
   # print 'result-keys: ', malwarelog['result'].keys()
   # print 'result-date-files: ', malware['result']['2018-10-30'][0]['total_physical_files_scanned']
   field_list = data['rows']
   file = open("data.csv","w")
   file.write("IP,ICSPName,partition_uuid,malware_filename,malware_name,action,total_physical_files_scanned,total_scanned_files,total_files,time,date\n")
   for fields in field_list:
       if (fields['custom_fields']['IP Address']['value'] is not None):
            # print(fields['custom_fields']['IP Address']['value'])
            ip = fields['custom_fields']['IP Address']['value']
            name = fields['name']
            print("The NAME is: ",name)
            response=os.system("ping -c 1 " + ip)
            # print("The response is: ", response)
            if response == 0:
                response = get_auth_session(ip)
                # print("The response code is: ",response.status_code)
                if (response.status_code == 200):
                    # print (response.status_code)
                    NNP_SESSION = response.cookies.get_dict()
                    # print("The NNP is: ", NNP_SESSION)

                    malwarelog = (get_malwarelogmultiple(NNP_SESSION, ip))

                    #Used when identifying the json fields to parse
                    #print 'keys in json:', data1.keys()
                    # print('result-keys: ', malwarelog['result'].keys())
                    #print 'result-date-files: ', malware['result']['2018-10-30'][0]['total_physical_files_scanned']

                    # Parsing the get_user function API response
                    # Iterate each of the JSON records.  "page_items" is the first structure that you can iterate
                    field_list1 = malwarelog['result'].keys()
                    print("field_list1: ", field_list1)
                    total_files_scanned = 0
                    # file.write(ip)
                    for fields in field_list1:
                        # print("this is the fields var: ", fields)
                            #skip the annoying "total" json field in the ICSP response
                        # file.write(line)
                        if fields != "total":
                            # print(malwarelog['result'][fields][0]['total_physical_files_scanned'])
                            # total_physical_files_scanned = malwarelog['result'][fields][0]['total_physical_files_scanned']
                            # partition_uuid = malwarelog['result'][fields][0]['partition_uuid']
                            # malware_filename = malwarelog['result'][fields][0]['malware_filename']
                            # malware_name = malwarelog['result'][fields][0]['malware_name']
                            # action = malwarelog['result'][fields][0]['action']
                            # total_scanned_files = malwarelog['result'][fields][0]['total_scanned_files']
                            # total_files = malwarelog['result'][fields][0]['total_files']
                            # time = malwarelog['result'][fields][0]['time']
                            # date = malwarelog['result'][fields][0]['date']
                            # line = ip + "," + partition_uuid + "," + malware_filename + "," + malware_name + "," + action
                            # line = line + "," + str(total_physical_files_scanned) + "," + str(total_scanned_files) + "," + str(total_files)
                            # line = line  + "," + time  + "," + date + "\n"
                            # print(line)
                            # print("Total files scanned: ", total_files_scanned)
                            print("field is: ", fields)
                            for scan in malwarelog['result'][fields]:
                                print("scan is: ", scan['malware_filename'])
                                total_physical_files_scanned = scan['total_physical_files_scanned']
                                partition_uuid = scan['partition_uuid']
                                malware_filename = scan['malware_filename']
                                malware_name = scan['malware_name']
                                action = scan['action']
                                total_scanned_files = scan['total_scanned_files']
                                total_files = scan['total_files']
                                time = scan['time']
                                date = scan['date']
                                line = ip + "," + name + "," + partition_uuid + "," + malware_filename + "," + malware_name + "," + action
                                line = line + "," + str(total_physical_files_scanned) + "," + str(
                                    total_scanned_files) + "," + str(total_files)
                                line = line + "," + time + "," + date + "\n"
                                file.write(line)
                else:
                    next(iter)
            else:
                print ("Device is down", ip)
   file.close()


   print ("total files scanned:", total_files_scanned)



if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()
