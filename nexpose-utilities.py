#willperez007 - Nexpose Utility
import requests

http_proxy = "http://localhost:8080"
https_proxy = "https://localhost:8080"

proxyDict = {
    "http" : http_proxy,
    "https" : https_proxy

}
host = "" #FQDN
BasicAuth = ""

url = "https://" + host + ":3780/api/3/" #URL of nexpose server api

payload = {}
headers = {
  'Accept': 'application/json',
  'Accept-Encoding': 'deflate,zip',
  'Accept-Language': 'en-US',
  'Authorization': 'Basic' + BasicAuth + "'"
}

#response = requests.request("GET", url, headers=headers, data = payload)

#print(response.text.encode('utf8'))
#print(response.json());


def get_sites():

      #Get all sites in InsightVM

      #:returns: all sites


  r = requests.get(url + "sites", headers=headers, data = payload, proxies=proxyDict, verify=False)

  if r.status_code == requests.codes.ok:
    data1 = r.json()

    # Parsing the get_user function API response
    # Iterate each of the JSON records.  "page_items" is the first structure that you can interate
    field_list1 = data1['resources']
    for fields in field_list1:
      print(fields['name'], fields['id'], fields['assets'])
    return r.json()
  else:
    print('Error getting sites')
    print(r.json())
    sys.exit()

def get_site_assets(id):

    # Get all sites in InsightVM

    #:returns: Retrieves a paged resource of assets linked with the specified site.

    r = requests.get(url + "sites/" + id + "/assets", headers=headers, data=payload, proxies=proxyDict, verify=False)
    print r.json()

    if r.status_code == requests.codes.ok:
        data1 = r.json()

        # Parsing the get_user function API response
        # Iterate each of the JSON records.  "page_items" is the first structure that you can interate
        field_list1 = data1['resources']
        for fields in field_list1:
           print(fields['ip'])
        #return r.json()
    else:
        print('Error getting site assets')
        print(r.json())
        sys.exit()

def get_sites(id):

    # Get all sites in InsightVM

    #:returns: Retrieves a paged resource of assets linked with the specified site.

    r = requests.get(url + "sites/" + id, headers=headers, data=payload, proxies=proxyDict, verify=False)
    #print r.json()

    if r.status_code == requests.codes.ok:
        data1 = r.json()

        # Parsing the get_user function API response
        # Iterate each of the JSON records.  "page_items" is the first structure that you can interate
        #field_list1 = data1['resources']
        #for fields in field_list1:
        print(data1['assets'],data1['lastScanTime'])
        #return r.json()
    else:
        print('Error getting site assets')
        print(r.json())
        sys.exit()

def get_site_template(id):

    # Retrieves the resource of the scan template assigned to the site.

    #:returns:

    r = requests.get(url + "sites/" + id + "/scan_template", headers=headers, data=payload, proxies=proxyDict, verify=False)
    #print r.json()

    if r.status_code == requests.codes.ok:
        data1 = r.json()

        # Parsing the get_user function API response
        # Iterate each of the JSON records.  "page_items" is the first structure that you can interate
        #field_list1 = data1['resources']
        #for fields in field_list1:
        #print(data1['discovery'])


        #return r.json()
    else:
        print('Error getting site assets')
        print(r.json())
        sys.exit()

def main():

  #response = get_sites()
  #response = get_site_assets('675')
  response = get_sites('675')
  response = get_site_template('675')


if __name__ == "__main__":
      try:
        main()
      except KeyboardInterrupt:
        sys.exit()