# Snipe-IT Asset Mgt Utility
import jwt # PyJWT version 1.5.3 as of the time of authoring.
import uuid
#import requests # requests version 2.18.4 as of the time of authoring.
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
from datetime import datetime, timedelta

# Suppress cert warning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

http_proxy = "http://localhost:8080"
https_proxy = "https://localhost:8080"

proxyDict = {
    "http" : http_proxy,
    "https" : https_proxy

}

snipe_it_access_token = ""  #Enter API token

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

        resp = requests.get(URL, headers=headers, json=params, proxies=proxyDict, verify=False)

        if resp.status_code == requests.codes.ok:
            # return json.loads(resp.text)['access_token']
            return resp
        else:
            print('Error getting URL:' + url)
            print(resp.content())


def main():

    response = get_hardware()

    print(response.text)

    data = response.json()

    # Parsing the get_devices function API response
    # Iterate each of the JSON records.  "page_items" is the first structure that you can iterate
    # Used when identifying the json fields to parse
    print 'keys in json:', data.keys()
    # print 'result-keys: ', malwarelog['result'].keys()
    # print 'result-date-files: ', malware['result']['2022-10-30'][0]['total_physical_files_scanned']
    field_list = data['rows']
    for fields in field_list:
        if(fields['custom_fields']['IP Address']['value'] is not None):
            print (fields['custom_fields']['IP Address']['value'])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()