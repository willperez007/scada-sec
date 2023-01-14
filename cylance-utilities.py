#willperez007 - Cylance Utility
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


# 30 minutes from now
timeout = 1800
now = datetime.utcnow()
timeout_datetime = now + timedelta(seconds=timeout)
epoch_time = int((now - datetime(1970, 1, 1)).total_seconds())
epoch_timeout = int((timeout_datetime - datetime(1970, 1, 1)).total_seconds())
jti_val = str(uuid.uuid4())

#Enter the API information from Cylance
tid_val = "" # The tenant's unique identifier.
app_id = "" # The application's unique identifier.
app_secret = "" # The application's secret to sign the auth token with.


AUTH_URL = "https://protectapi.cylance.com/auth/v2/token"
claims = {
"exp": epoch_timeout,
"iat": epoch_time,
"iss": "http://cylance.com",
"sub": app_id,
"tid": tid_val,
"jti": jti_val
# The following is optional and is being noted here as an example on how one can restrict
# the list of scopes being requested
#"scp": "policy:read"
}



def get_access_token():
    print (claims)
    encoded = jwt.encode(claims, app_secret, algorithm='HS256')
    print ("auth_token:\n" + encoded.decode() + "\n")
    payload = {"auth_token": encoded.decode()}
    headers = {"Content-Type": "application/json; charset=utf-8"}
    resp = requests.post(AUTH_URL, headers=headers, proxies=proxyDict, data=json.dumps(payload),verify=False)
    #print "http_status_code: " + str(resp.status_code)
    #print "access_token:\n" + json.loads(resp.text)['access_token'] + "\n"
    #print json.loads(resp.text)

    if resp.status_code == requests.codes.ok:
        return json.loads(resp.text)['access_token']
        #return resp
    else:
     print('Error getting URL:' + url)
     print(resp.content())
    sys.exit()

def get_users(access_token):
    URL = "https://protectapi.cylance.com/users/v2?page=1&page_size=200"
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application / json",
        "Authorization": "Bearer " + access_token
    }

    resp = requests.get(URL, headers=headers, proxies=proxyDict, verify=False)

    if resp.status_code == requests.codes.ok:
        #return json.loads(resp.text)['access_token']
        return resp
    else:
        print('Error getting URL:' + url)
        print(resp.content())

def get_user(access_token,email):

    URL = "https://protectapi.cylance.com/users/v2/" + email
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application / json",
        "Authorization": "Bearer " + access_token
    }

    resp = requests.get(URL, headers=headers, proxies=proxyDict, verify=False)

    if resp.status_code == requests.codes.ok:
        #return json.loads(resp.text)['access_token']
        return resp
    else:
        print('Error getting URL:' + url)
        print(resp.content())

def get_devices(access_token):

    URL = "https://protectapi.cylance.com/devices/v2/"
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application / json",
        "Authorization": "Bearer " + access_token
    }

    resp = requests.get(URL, headers=headers, proxies=proxyDict, verify=False)

    if resp.status_code == requests.codes.ok:
        #return json.loads(resp.text)['access_token']
        return resp
    else:
        print('Error getting URL:' + url)
        print(resp.content())


def get_global_list(access_token):
    URL = "https://protectapi.cylance.com/globallists/v2?listTypeId=0"
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application / json",
        "Authorization": "Bearer " + access_token
    }

    resp = requests.get(URL, headers=headers, proxies=proxyDict, verify=False)

    if resp.status_code == requests.codes.ok:
        # return json.loads(resp.text)['access_token']
        return resp
    else:
        print('Error getting URL:' + url)
        print(resp.content())

#def main():


    access_token = get_access_token()
    #response = get_users(access_token)
    #reponse = get_global_list(access_token)
    response = get_user(access_token,"wperez@rccl.com")
    response2 = get_devices(access_token)
    print (response.json())
    print (response2.json())

def main():

        access_token = get_access_token()

        response = get_users(access_token)
        response2 = get_devices(access_token)

        # Decode the JSON Response
        data1 = response.json()
        data2 = response2.json()

        # Parsing the get_user function API response
        # Iterate each of the JSON records.  "page_items" is the first structure that you can interate
        field_list1 = data1['page_items']
        for fields in field_list1:
            print(fields['email'])

        # Parsing the get_devices function API response
        # Iterate each of the JSON records.  "page_items" is the first structure that you can interate
        field_list2 = data2['page_items']
        for fields in field_list2:
            print(fields['ip_addresses'])



if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()