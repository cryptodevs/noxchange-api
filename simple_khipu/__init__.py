import hashlib
import hmac
import requests
import json
from urllib import quote

URL = 'https://khipu.com/api/2.0/'

def sign_message(secret, method, service, json_data):
    """
    Generates valid hash for requests
    """
    decoded = "{0}&".format(method)
    decoded += quote("{0}{1}".format(URL, service), safe='')
    if json_data is not "":
        decoded += format_data(json_data)
    return(hmac.new(str(secret), str(decoded), hashlib.sha256).hexdigest())

def format_data(json_data):
    response = ""
    data = json.loads(json_data)
    for k,v in sorted(data.items()):
        response += "&{0}={1}".format(quote(k, safe=''), quote(str(v), safe=''))

    return response

def make_request(user_id, method, service, secret, json_data):
    headers = {
        'Authorization': '{}:{}'.format(user_id, sign_message(secret, method, service, json_data))
    }
    
    if method is 'POST':
        payload = json.loads(json_data)
        req = requests.post('{0}{1}'.format(URL, service),headers=headers,data=payload)
    else:
        payload = format_data(json_data)
        req = requests.get('{0}{1}?{2}'.format(URL,service,payload),headers=headers)
    return req.text

def create_payment(user_id, secret, json_data):
    """
    https://khipu.com/page/api-referencia#paymentsPost
    """
    method = 'POST'
    service = 'payments'
    return make_request(user_id, method, service, secret, json_data)

def check_payment(user_id, secret, json_data):
    """    
    https://khipu.com/page/api-referencia#paymentsGet
    """
    method = 'GET'
    service = 'payments'
    return make_request(user_id, method, service, secret, json_data)    
