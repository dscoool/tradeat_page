import jwt 
import uuid
import hashlib
import time
from urllib.parse import urlencode
import requests
import json
import pandas as pd

class Bitthumb:
    def __init__(self):
        self.accessKey = 'b6692bb7bea03e2b73c802ca599f000cd09bdb55603605'
        self.secretKey = 'MDMxZmZlODI0ZmEwYTQxMDI3YmFiMGFlM2UyMDAwYjgwNGNlNWU5ZDAwMGFkNzk5ZGY1NzYxMzQwY2JkOQ=='
        self.apiUrl = 'https://api.bithumb.com'
        self.payload = self.generate_payload()
        if self.market == 'ALL':
            self.market = pd.NULL
            
    def generate_payload(self):
        payload = {
            'access_key': self.accessKey,
            'nonce': str(uuid.uuid4()),
            'timestamp': round(time.time() * 1000),
        }
        return payload

    def generate_jwt_token(self, payload):
        query = urlencode(payload).encode()
        hash = hashlib.sha512()
        hash.update(query)
        query_hash = hash.hexdigest()
        payload.update({'query_hash': query_hash, 'query_hash_alg': 'SHA512'})
        jwt_token = jwt.encode(payload, self.secretKey)
        return 'Bearer {}'.format(jwt_token)
    
    def order_status(self,market):
        # Set API parameters
        param = dict( market=market, limit=100, page=1, order_by='desc' )
        uuids = [
            # 'C0106000032400700021', 'C0106000043000097801'
        ]
        query = urlencode(param)
        # uuid_query = '&'.join([f'uuids[]={uuid}' for uuid in uuids])
        # query = query + "&" + uuid_query
        # Generate access token
        hash = hashlib.sha512()
        hash.update(query.encode())
        query_hash = hash.hexdigest()
        payload = {
            'access_key': self.accessKey,
            # 'nonce': str(uuid.uuid4()),
            'timestamp': round(time.time() * 1000), 
            'query_hash': query_hash,
            'query_hash_alg': 'SHA512',
        }   
        jwt_token = jwt.encode(payload, self.secretKey)
        authorization_token = 'Bearer {}'.format(jwt_token)
        headers = {
        'Authorization': authorization_token
        }
        try:
            # Call API
            response = requests.get(self.apiUrl + '/v1/orders?' + query, headers=headers)
            # handle to success or fail
            result_code=response.status_code
            order_receipt = response.json()
        except Exception as err:
            # handle exception
            order_receipt="##### Error occured!"
            result_code=err
        return self.json2df(order_receipt), result_code
    
    def json2df(self, json_data):
        if isinstance(json_data, str):
            json_data = json.loads(json_data)
        df = pd.DataFrame(json_data)
        return df
    
    def long_order(self, market, volume, price, ord_type="limit"):
        # Set API parameters
        # requestBody = dict( market='KRW-BTG', side='bid', volume='55.0', price=23000, ord_type='limit' )
        requestBody = dict( market=market, side='bid', volume=volume, price=price, ord_type=ord_type )

        # Generate access token
        query = urlencode(requestBody).encode()
        hash = hashlib.sha512()
        hash.update(query)
        query_hash = hash.hexdigest()
        self.payload.update({'query_hash': query_hash,
                     'query_hash_alg': 'SHA512'})
        jwt_token = jwt.encode(self.payload, self.secretKey)
        authorization_token = 'Bearer {}'.format(jwt_token)
        headers = {
        'Authorization': authorization_token,
        'Content-Type': 'application/json'
        }

        try:
            # Call API
            response = requests.post(self.apiUrl + '/v1/orders', data=json.dumps(requestBody), headers=headers)
            # handle to success or fail
            result_code = response.status_code
            order_receipt = response.json()
        except Exception as err:
            # handle exception
            result_code = err
        # self.recent_order_uuid = order_receipt['uuid']
        return order_receipt, result_code
        
    def longclose_order(self, market, volume, price, ord_type="limit"):
        # Set API parameters
        requestBody = dict( market=market, side='ask', volume=volume, price=price, ord_type=ord_type )
        # Generate access token
        query = urlencode(requestBody).encode()
        hash = hashlib.sha512()
        hash.update(query)
        query_hash = hash.hexdigest()
        self.payload.update({'query_hash': query_hash,
                     'query_hash_alg': 'SHA512'})
        jwt_token = jwt.encode(self.payload, self.secretKey)
        authorization_token = 'Bearer {}'.format(jwt_token)
        headers = {
        'Authorization': authorization_token,
        'Content-Type': 'application/json'
        }

        try:
            # Call API
            response = requests.post(self.apiUrl + '/v1/orders', data=json.dumps(requestBody), headers=headers)
            # handle to success or fail
            result_code = response.status_code
            order_receipt = response.json()
        except Exception as err:
            # handle exception
            result_code = err
        
        return order_receipt, result_code
    
    
    def cancel_order(self, uuid):
        # Set API parameters
        param = dict( uuid=uuid )

        # Generate access token
        query = urlencode(param).encode()
        hash = hashlib.sha512()
        hash.update(query)
        query_hash = hash.hexdigest()
        # Set API parameters
        payload = self.generate_payload()  # Assuming you have this function defined
        payload.update({
            'uuid': uuid,
            'query_hash': query_hash,
            'query_hash_alg': 'SHA512'
        })
        jwt_token = jwt.encode(payload, self.secretKey)
        authorization_token = 'Bearer {}'.format(jwt_token)
        headers = {
        'Authorization': authorization_token
        }

        try:
            # Call API
            response = requests.delete(self.apiUrl + '/v1/order', params=param, headers=headers)
            # handle to success or fail
            result_code = response.status_code
            order_receipt = response.json()
        except Exception as err:
            # handle exception
            result_code = err

        return order_receipt, result_code
    
    def asset_status(self):
        # payload = self.payload
        jwt_token = jwt.encode(self.payload, self.secretKey)
        authorization_token = 'Bearer {}'.format(jwt_token)
        headers = {
            'Authorization': authorization_token
        }
        try:
            # Call API
            response = requests.get(self.apiUrl + '/v1/accounts', 
                                    headers=headers)
            # handle to success or fail
            result_code=response.status_code
            asset_status = response.json()
        except Exception as err:
            # handle exception
            result_code=err
        return self.json2df(asset_status), result_code
    
    def current_price(self, market):
        url = "https://api.bithumb.com/v1/ticker?markets="+market
        headers = {"accept": "application/json"}
        response = requests.get(url, headers=headers)
        # return response.text
        return response.json()

if __name__ == "__main__":
    market=''
    bit = Bitthumb()
    # print(str(market)+': '+str(bit.current_price(market)))

    ### Order List
    receipt, result_code = bit.order_status(market)

    ### Long
    # receipt, result_code = bit.long_order(market=market, 
    #                                         volume='5', 
    #                                         price=21000, 
    #                                     )
    ### Cancel Order
    # receipt, result_code = bit.cancel_order(uuid = 'C0111000000110620092')
    
    
    #### LongClose
    # receipt, result_code = bit.longclose_order(market=market, 
    #                     volume='49', 
    #                     price=3464, 
    #                     ord_type='limit')

    # ## Log transactions
    print(str(result_code)+' | '+ str(receipt)) 
    ## LOG HERE
    
    ## Asset Status
    # asset, result_code = bit.asset_status()
    # print(result_code)
    # print(asset)

  