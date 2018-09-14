---
title: API Reference

language_tabs: # must be one of https://git.io/vQNgJ

  - java
  - ruby
  - python
  - php
  - csharp
  - cURL
  - json

toc_footers:
  - <a href='https://www.epiapi.com'>Visit us!</a>

search: true

---

# Overview


epiapi is focused on enterprise tools that improve accessibility and usability of financial services across borders. We offer a powerful REST API that supports virtual banking services for enterprises, through our parent company Wyre.


Our API uses HTTPS response codes and returns all error responses in JSON. To explore the API as much as possible, we offer a test environment in addition to production. Any transfers made in the test environment will not be executed. Both sandbox and production rely on API keys for authentication.


# Getting Started


This guide is written as a standard implementation of our virtual banking service for setting up an environment to create US bank accounts for merchants selling on Amazon. Through this implementation you will be able to pass the necessary KYC information in order to open a virtual bank account, receive the bank account number, monitor for receivables, and manage funds for delivery to a designated bank account. All integrations will require a signed agreement with epiapi - please reach out to us at: [contact@epiapi.com](mailto:cotact@epiapi.com) if you do not have an agreement in place or for any other questions.


Check out the [Chinese Version](https://epi-api.github.io/slate-zh/).


- - -

**How to get Started**


**Step 1. Read the documentation**

You are already doing this. Congratulations!


**Step 2. Register a test account**

Sign up [here](https://www.testwyre.com) to interact with our test environment. No need to upload any documents for the test envornment (though this will be required on production) - jump straight to Step 3.


**Step 3. Verify your test account**

Contact our support team at [support@epiapi.com](mailto:support@epiapi.com) so we can verify your test account and add test funds that you can start using. The test API does not execute real transactions so feel free to go crazy.


**Step 4. Get Support**

We will send you links to join us on Slack or other chat apps (DingTalk, QQ etc) - any questions just ask!


**Step 5. Register a production account**

Once testing has completed, you can register a live account [here](https://www.sendwyre.com). You must go through the entire onboarding and verification process before you are allowed to interact with the account.


**Step 6. Go live!**

Once fully onboarded you are ready to go!


# General

## Supported Countries

Our Virtual banking product currently accepts USD via ACH to a domestic US bank account.

**Countries**

- United States
- European Union (coming soon)
- Australia (coming soon)

We are adding more countries soon. We will send an email as and when we release new functionality:)

**Currencies**

- USD
- EUR (coming soon)
- GBP (coming soon)
- AUD (coming soon)


## Transport Method

We provide a REST API that will always return a JSON Object as the response.


If the error response is in a different format it's problem not something wrong with epiapi but customers' server.


```json
For successful API calls:
{
        "parameter": "en",
        "parameter": "ABCDEF"

}

For unsuccessful API calls:
{
        "language":"en",
        "exceptionId":"ABCDEF",
        "compositeType":"",
        "subType":"",
        "message":"Error Message",
        "type":"ErrorTypeException",
        "transient":false
}
```


## Production/Test Endpoints

We have two environments, `testwyre` for API integration testing and `sendwyre`, our production environment.


Environment | Endpoint
--------- | -----------
Test | <a href="https://api.testwyre.com"> https://api.testwyre.com </a>
Production | <a href="https://api.sendwyre.com"> https://api.sendwyre.com </a>


## Pagination

We split our tabular data into pages of 25 items. You can apply the parameters below to any request to adjust the pagination.


Parameter | Description
--------- | -----------
offset | How many items are skipped before the first item that is shown (default: 0).
limit | Number of items returned per page (default: 25).
from | The lower bound of a creation time filter for the displayed items. Formatted in millisecond Epoch format. (default: 0)
to | The upper bound of a creation time filter for the displayed items. Formatted in millisecond Epoch format. (default: current time)


## Authentication


```ruby
require 'uri'
require 'net/http'
require 'digest/hmac'
require 'json'

class WyreApi
  ACCOUNT_ID = 'YOUR_ACCOUNT_ID_HERE'
  API_KEY = 'YOUR_API_KEY_HERE'
  SEC_KEY = 'YOUR_SECRET_KEY_HERE'
  API_URL = 'https://api.testwyre.com'

  def create_transfer options
    api_post '/transfers', options
  end

  private

  def api_post path, post_data = {}
    params = {
      'timestamp' => (Time.now.to_i * 1000).to_s
    }

    url = API_URL + path + '?' + URI.encode_www_form(params)

    headers = {
      'X-Api-Key' => API_KEY,
      'X-Api-Signature' => calc_auth_sig_hash(url + post_data.to_json.to_s),
      'X-Api-Version' => '2'
    }

    uri = URI API_URL
    Net::HTTP.start(uri.host, uri.port, :use_ssl => true) do |http|
      http.request_post(url, post_data.to_json.to_s, headers) do |res|
        response = JSON.parse res.body
        raise response['message'] if res.code != '200'
        return response
      end
    end
  end

  def calc_auth_sig_hash url_body
    return Digest::HMAC.hexdigest url_body, SEC_KEY, Digest::SHA256
  end
end

api = WyreApi.new
api.create_transfer({'sourceAmount'=>50,'sourceCurrency'=>'USD','dest'=>'richard@epiapi.com', 'destCurrency'=>'USD', 'message'=>'buy Richard pizza')
```

```python
#dependencies:
#python3
#pip3 install requests

import json
import hmac
import time
from requests import request

class MassPay_API(object):
    def __init__(self, account_id, api_version, api_key, api_secret):
        self.account_id = account_id
        self.api_url = 'https://api.testwyre.com/{}'.format(api_version)
        self.api_version = api_version
        self.api_key = api_key
        self.api_secret = api_secret

    #authentication decorator. May raise ValueError if no json content is returned
    def authenticate_request(func):
        def wrap(self, *args, **kwargs):
            url, method, body = func(self, *args, **kwargs)
            params = {}
            timestamp = int(time.time() * 1000)
            url += '?timestamp={}'.format(timestamp)
            bodyJson = json.dumps(body) if body != '' else ''
            headers = {}
            headers['Content-Type'] = 'application/json'
            headers['X-Api-Version'] = self.api_version
            headers['X-Api-Key'] = self.api_key
            headers['X-Api-Signature'] = hmac.new(self.api_secret.encode('utf-8'), (url + bodyJson).encode('utf-8'), 'SHA256').hexdigest()
            print(headers['X-Api-Signature'])
            resp = request(method=method, url=url, params=params, data=(json.dumps(body) if body != '' else None), json=None, headers=headers)
            if resp.text is not None: #Wyre will always try to give an err body
                return resp.status_code, resp.json()
            return 404, {}
        return wrap

    @authenticate_request
    def retrieve_exchange_rates(self):
        url = self.api_url + '/rates'
        method = 'GET'
        body = ''
        return url, method, body

    @authenticate_request
    def retrieve_account(self):
        url = self.api_url + '/account'
        method = 'GET'
        body = ''
        return url, method, body

    @authenticate_request
    def create_transfer(self, sourceAmount, sourceCurrency, destAmount, destCurrency, destAddress, message, autoConfirm):
        url = self.api_url + '/transfers'
        method = 'POST'
        #ONLY use either sourceAmount or destAmount, see documentation
        body = {'sourceCurrency':sourceCurrency,
                'dest':destAddress,
                'destCurrency':destCurrency,
                'message':message}
        if sourceAmount:
            body["sourceAmount"] = sourceAmount
        elif destAmount:
            body["destAmount"] = destAmount
        if autoConfirm:
            body['autoConfirm'] = True
        return url, method, body

    @authenticate_request
    def confirm_transfer(self, transfer_id):
        url = self.api_url + '/transfer/{}/confirm'.format(transfer_id)
        method = 'POST'
        body = ''
        return url, method, body  

    @authenticate_request
    def status_transfer(self, transfer_id):
        url = self.api_url + '/transfer/{}'.format(transfer_id)
        method = 'GET'
        body = ''
        return url, method, body  

#USAGE Example
account_id = "YOUR_ACCOUNT_ID_HERE" #optional
api_key = "YOUR_API_KEY_HERE"
secret_key = "YOUR_SECRET_KEY_HERE"
api_version = "2"

#create Wyre MassPay API object
Wyre = MassPay_API(account_id, api_version, api_key, secret_key)

#get account info
http_code, account = Wyre.retrieve_account()
print(account)
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.Integer;
import java.lang.String;
import java.lang.StringBuffer;
import java.net.HttpURLConnection;
import java.net.URL;

public class TestAuth {
  public static void main(String[] args) {
    String apiKey = "YOUR_API_KEY_HERE";
    String secretKey = "YOUR_SECRET_KEY_HERE";

    String url = "https://api.testwyre.com/account";
    String method = "GET";
    String data = "";

    String result = executeWyreRequest(url, "", method, apiKey, secretKey);
    System.out.println(result);

    url = "https://api.testwyre.com/transfers";
    method = "POST";
    data = "{" +
        "  \"dest\": \"richard@epiaapi.com\"," +
        "  \"destCurrency\": \"USD\"," +
        "  \"sourceCurrency\" : \"USD\"," +
        "  \"sourceAmount\" : \"50\"," +
        "  \"message\": \"buy Richard pizza\"" +
        "}";
    result = executeWyreRequest(url, data, method, apiKey, secretKey);

    System.out.println(result);
  }

  public static String executeWyreRequest(String targetURL, String requestBody, String method, String apiKey, String secretKey) {
    URL url;
    HttpURLConnection connection = null;
    try {

      targetURL += ((targetURL.indexOf("?")>0)?"&":"?") + "timestamp=" + System.currentTimeMillis();

      //Create connection
      url = new URL(targetURL);
      connection = (HttpURLConnection)url.openConnection();
      connection.setRequestMethod(method);
      System.out.println(connection.getRequestMethod());

      connection.setRequestProperty("Content-Type", "application/json");
      connection.setRequestProperty("Content-Length", Integer.toString(requestBody.getBytes().length));

      //Specify API v2
      connection.setRequestProperty("X-Api-Version","2");

      // Provide API key and signature
      connection.setRequestProperty("X-Api-Key", apiKey);
      connection.setRequestProperty("X-Api-Signature",computeSignature(secretKey,targetURL,requestBody));

      //Send request
      if(method.equals("POST")) {
        connection.setDoOutput(true);
        connection.setRequestMethod(method);

        DataOutputStream wr = new DataOutputStream(
            connection.getOutputStream());

        wr.write(requestBody.getBytes("UTF-8"));
        wr.flush();
        wr.close();
      }

      //Get Response
      InputStream is;
      if (connection.getResponseCode() < HttpURLConnection.HTTP_BAD_REQUEST) {
        is = connection.getInputStream();
      } else {

        is = connection.getErrorStream();
      }

      BufferedReader rd = new BufferedReader(new InputStreamReader(is));
      String line;
      StringBuffer response = new StringBuffer();
      while((line = rd.readLine()) != null) {
        response.append(line);
        response.append('\r');
      }
      rd.close();
      return response.toString();

    } catch (Exception e) {

      e.printStackTrace();
      return null;

    } finally {

      if(connection != null) {
        connection.disconnect();
      }
    }
  }

  public static String computeSignature(String secretKey, String url, String reqData) {

    String data = url + reqData;

    System.out.println(data);

    try {
      Mac sha256Hmac = Mac.getInstance("HmacSHA256");
      SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
      sha256Hmac.init(key);

      byte[] macData = sha256Hmac.doFinal(data.getBytes("UTF-8"));

      String result = "";
      for (final byte element : macData){
        result += Integer.toString((element & 0xff) + 0x100, 16).substring(1);
      }
      return result;

    } catch (Exception e) {
      e.printStackTrace();
      return "";
    }
  }
}
```

```php
<?php
    function make_authenticated_request($endpoint, $method, $body) {
        $url = 'https://api.testwyre.com';
        $api_key = "YOUR_API_KEY_HERE";
        $secret_key = "YOUR_SECRET_KEY_HERE";

        $timestamp = floor(microtime(true)*1000);
        $request_url = $url . $endpoint;

        if(strpos($request_url,"?"))
            $request_url .= '&timestamp=' . $timestamp;
        else
            $request_url .= '?timestamp=' . $timestamp;

        if(!empty($body))
            $body = json_encode($body, JSON_FORCE_OBJECT);
        else
            $body = '';

        $headers = array(
            "Content-Type: application/json",
            "X-Api-Key: ". $api_key,
            "X-Api-Signature: ". calc_auth_sig_hash($secret_key, $request_url . $body),
            "X-Api-Version: 2"
        );
        $curl = curl_init();

        if($method=="POST"){
          $options = array(
            CURLOPT_URL             => $request_url,
            CURLOPT_POST            =>  true,
            CURLOPT_POSTFIELDS      => $body,
            CURLOPT_RETURNTRANSFER  => true);
        }else {
          $options = array(
            CURLOPT_URL             => $request_url,
            CURLOPT_RETURNTRANSFER  => true);
        }
        curl_setopt_array($curl, $options);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        $result = curl_exec($curl);
        curl_close($curl);
        var_dump($result);
        return json_decode($result, true);
    }

    function calc_auth_sig_hash($seckey, $val) {
        $hash = hash_hmac('sha256', $val, $seckey);
        return $hash;
    }

    echo make_authenticated_request("/account", "GET", array());
    $transfer = array(
      "sourceCurrency"=>"USD",
      "dest"=>"richard@epiapi.com",
      "sourceAmount"=> 50,
      "destCurrency"=>"USD",
      "amountIncludesFees"=>True
      "message"=> "buy Richard pizza"
      );
    echo make_authenticated_request("/transfers", "POST", $transfer);
    ?>
```

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
namespace testauthwyre
{
    class MainClass
    {
        public static void Main(string[] args)
        {
            WyreApi wyre = new WyreApi();
            Console.WriteLine(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            Console.WriteLine((long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds);
            HttpWebResponse accountResponse = wyre.Get("/account");
            Console.WriteLine(GetResponseBody(accountResponse));
            Dictionary<string, object> body = new Dictionary<string, object>();
            body.Add("sourceCurrency", "USD");
            body.Add("sourceAmount", "50");
            body.Add("dest", "richard@epiapi.com");
            HttpWebResponse transferResponse = wyre.Post("/transfers", body);
            Console.WriteLine(GetResponseBody(transferResponse));
        }
        private static string GetResponseBody(HttpWebResponse response)
        {
            return JObject.Parse(new StreamReader(response.GetResponseStream()).ReadToEnd()).ToString(Formatting.Indented);
        }
    }
    public class WyreApi
    {
        private const String domain = "https://api.testwyre.com";
        private const String apiKey = "YOUR_API_KEY_HERE";
        private const String secKey = "YOUR_SECRET_KEY_HERE";
        public HttpWebResponse Get(string path)
        {
            return Get(path, new Dictionary<string, object>());
        }
        public HttpWebResponse Get(string path, Dictionary<string, object> queryParams)
        {
            return Request("GET", path, queryParams);
        }
        public HttpWebResponse Post(string path, Dictionary<string, object> body)
        {
            return Request("POST", path, body);
        }
        private HttpWebResponse Request(string method, string path, Dictionary<string, object> body)
        {
            Dictionary<string, object> queryParams = new Dictionary<string, object>();
            if (method.Equals("GET"))
                queryParams = body;
            queryParams.Add("timestamp", GetTimestamp());
            string queryString = queryParams.Aggregate("", (previous, current) => previous + "&" + current.Key + "=" + current.Value).Remove(0, 1);
            string url = domain + path + "?" + queryString;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = method;
            request.ContentType = "application/json";
            request.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
            if (!method.Equals("GET"))
            {
                url += JsonConvert.SerializeObject(body);
                using (StreamWriter writer = new StreamWriter(request.GetRequestStream()))
                    writer.Write(JsonConvert.SerializeObject(body));
            }
            request.Headers["X-Api-Key"] = apiKey;
            request.Headers["X-Api-Signature"] = CalcAuthSigHash(secKey, url);
            request.Headers["X-Api-Version"] = "2";
            try
            {
                return (HttpWebResponse)request.GetResponse();
            }
            catch(WebException e)
            {
                string msg = new StreamReader(e.Response.GetResponseStream()).ReadToEnd();
                Console.WriteLine(msg);
                throw new SystemException(msg);
            }
        }
        private byte[] GetBytes(string str)
        {
            return Encoding.UTF8.GetBytes(str);
        }
        private string GetString(byte[] bytes)
        {
            return BitConverter.ToString(bytes);
        }
        private long GetTimestamp()
        {
            // return DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() // .NET 4.6
            return (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;
        }
        private String CalcAuthSigHash(string key, string value)
        {
            HMACSHA256 hmac = new HMACSHA256(GetBytes(key));
            string hash = GetString(hmac.ComputeHash(GetBytes(value))).Replace("-", "");
            return hash;
        }
    }
}
```

We use a handful of security mechanisms to ensure that your requests are secure. You can find information on how to make a secure authenticated request below.


In order to make an authenticated request you'll need to pass a couple of values through the HTTP headers with your request:


HTTP Header Field | Description
--------- | -----------
X-Api-Key | Your API key. Your key can be found <a href="https://epiapi.zendesk.com/hc/en-us/articles/360009109612-API-Key-%E8%AE%BE%E7%BD%AE%E6%8C%87%E5%8D%97">here</a>
X-Api-Signature | A signature used to verify the request was sent by the account holder. See [Calculating the request signature](#calculating-the-request-signature).


Additionally, you should include a `GET` parameter named timestamp which is the current time in **millisecond epoch format**. We use this timestamp to help protect against replay attacks.


## Calculating the request signature

If you are sending a `GET` request you would sign the following (example):  *https://api.testwyre.com/v2/rates?timestamp=1426252182534*


If you are making a `POST` request you would sign the following (example): *https://api.testwyre.com/v2/transfers?timestamp=1426252182534*


Note for the `POST` request, you must append the request body to the string URL. Remember to send the request body exactly as you sign it, whitespace and all. The server calculates the signature based on exactly what's in the request body.


**Calculating the X-Api-Signature field is a two step process:**

1. Concatenate the request URL with the body of the HTTP request into a UTF-8 String. Use an empty string for the HTTP body in `GET` requests.

2. Compute the signature using HMAC with SHA-256 and your API Secret Key.


## SRNs

An SRN is a System Resource Name. It is a typed identifier that may reference any object within our platform. Many of our API calls and data schemas leverage SRNs in order to add flexibility and decouple services. All SRNs follow the same format:


type | Identifier
--------- | -----------
contact | A contact id (contact:CO-123123123)
paymentmethod | A payment method such as a bank account (paymentmethod:PA-123123123)
email | An email address (email:test@epiapi.com)
cellphone | A cellphone number (cellphone:+8615555555555)
account | A plaform account (account:AC-123123123)
wallet | A single wallet (wallet:WA-123123123)
transfer | A transfer (possibly including a conversion) of currency (transfer:TF-123123123)


## Fees

Fees are caluculated by our system based on the contract signed by both parties. Our standard fee for VBA + daily settlement is 0.25%.

## Error Table

Successful requests will be a HTTP 200 response after any successful call. The body of successful requests depend on the endpoint.


Whenever a problem occurs, we will respond to the client using a 4xx or 5xx status code. In this case, the body of the response will be an exception object which describes the problem.


Exception | Description | HTTPs Status Code
--------- | ----------- | -----------
ValidationException | The action failed due to problems with the request. | 400
UnknownException | A problem with our services internally. This should rarely happen. | 500
InsufficientFundsException | You requested the use of more funds in the specified currency than were available. | 400
RateLimitException | Your requests have exceeded your usage restrictions. Please contact us if you need this increased. | 429
AccessDeniedException | You lack sufficient privilege to perform the requested action. | 401
TransferException | There was a problem completing your transfer request. | 400
NotFoundException | You requested something that couldn't be located. | 400
ValidationException | There was a problem validating the input you supplied. | 400
CustomerSupportException | Please contact us at support@epiapi.com to resolve this! | 400
MFARequiredException | An MFA action is required to complete the request. In general you should not get this exception while using API keys. | 400


All exceptions will carry a subType parameter which exposes more information about the problem. Additionally, some ValidationException errors will carry with them two fields, problematicField and problematicValue, denoting the field which caused the failure.


**A few typical ValidationException subtypes:**


FIELD_REQUIRED

INVALID_VALUE

TRANSACTION_AMOUNT_TOO_SMALL

UNSUPPORTED_SOURCE_CURRENCY

CANNOT_SEND_SELF_FUNDS

INVALID_PAYMENT_METHOD

PAYMENT_METHOD_INACTIVE

PAYMENT_METHOD_UNSUPPORTED_CHARGE_CURRENCY

PAYMENT_METHOD_UNCHARGEABLE

PAYMENT_METHOD_UNSUPPORTED_DEPOSIT_CURRENCY


# Step-by-step Guide

This guide will take you through all steps required to build a funds receivables product based on our API.

## Virtual Banking

**Building a USD receivables business on epiapi**

There are many different ways to integrate with our API to provide different types of payments receivables services. To help developers understand how it may be used, we’ve described a typical use-case below.


We will show you an example of how an online platform may create USD virtual bank accounts with unique account numbers for its users, and receive funds for delivery into a dedicated settlement account.

### Step 1. Create a Wallet with KYC Data

Wyre uses the concept of `wallets` to represent individual merchant accounts under your `account`. Upon creation, each of these wallets are assigned various fund receiving capabilities. You must set `type=VBA` in order to obtain a Virtual Bank Account (with a unique bank account and routing number).


`POST` https://api.testwyre.com/v2/wallets


<pre class="center-column">
{
  "name":"youruniquename",
  "type":"VBA",
  "callbackUrl":"https://your.website.io/callback",
  "vbaVerificationData":{
    "entityType":"CORP",
    "entityScope":"Shopping/Retail",
    "email":"test+merchant@epiapi.com",
    "phoneNumber":"13111111111",
    "ip": "127.0.0.1",
    "nameCn":"法人姓名",
    "nameEn":"Legal Rep",
    "dateOfBirth":1514736000,
    "address":{
      "city":"北京",
      "country":"CN",
      "postalCode":"210000",
      "street1":"东四北大街107号",
      "street2":"克林大厦107室"},
    "idNumber":"432524199902287897",
    "idDoc":null,
    "merchantIds":[{
    "merchantId":"AAAAAAAAAAA",
    "merchantType":"Amazon"}],
    "expectedMonthlySales":40000,
    "shopName":"MyBrand",
    "website":"https://merchant.website.com",
    "repAaddress":{
      "city":"北京",
      "country":"CN",
      "postalCode":"210000",
      "street1":"东四北大街107号",
      "street2":"克林大厦107室"},
    "companyNameCn":"ABC有限责任公司",
    "companyNameEn":"ABC Company Limited",
    "registrationNumber":"123456789",
    "coiDoc":null,
    "salesDoc":null,
    "dateOfEstablishment":1514736000,
    "beneficialOwners":[{
      "fullName":"Richard",
      "idNumber":"1231321312",
      "idDoc":null}]
      }
}
</pre>


<br>


Fields(* means mandatory)| Description
---------|-----------
"entityType" * | "CORP"、“M”、“F” available
"entityScope" * | "Shopping/Retail"
"email" * | "test+merchant@epiapi.com"
"phoneNumber" * | "13111111111"
"ip" * | The IP address of the user when opening the acount
"nameCn" * | "法人姓名"
"nameEn" * | "Legal Rep"
"dateOfBirth" * | UNIX (milliseconds)
"address" * | (street 2 can be bland if not needed)
"street1" | "东四北大街107号"
"street2" | "克林大厦107室"
"city" | "beijing"
"state" | "beijing"
"country" |"CN"
"postalCode" | "100007"
"idNumber" * | "432524199902287897"
"idDoc" * | null
"merchantId" | "A00000"
"merchantType" | "Amazon"
"expectedMonthlySales" | 40000
"shopName" | "MyBrand"
"website" | "https://merchant.website.com"
"repAaddress"(* CORP only) | (street 2 can be blank if not needed)
"street1"| "东四北大街107号"
"street2"| "克林大厦107室"
"city"| "beijing"
"state" | "beijing"
"country"| "CN"
"postalCode" | "100007"
"companyNameCn"(* CORP only)| "ABC有限责任公司"
"companyNameEn"( * CORP only)| "ABC Company Limited"
"registrationNumber"(* CORP only)| "123456789"
"coiDoc"(* CORP only)| null
"salesDoc"(may be required for high volume clients) | null
"dateOfEstablishment" * | UNIX (milliseconds)
"beneficialOwners"(HK CORP only) |
"fullName"| "Richard"
"idNumber"| "1231321312"
"idDoc"| null



```cURL
curl -v -XPOST 'https://api.testwyre.com/v2/wallets' \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: {api-key}" \
  -H "X-Api-Signature: {signature}" \
  -d '{"type":"VBA","name":"{your-unique-identifier}"
```

```json
{
  "callbackUrl":"https://your.website.io/callback",
  "name":"12345678977897800",
  "type":"VBA",
  "vbaVerificationData":{
    "entityType":"CORP",
    "entityScope":"Shopping/Retail",
    "email":"test+merchant@epiapi.com",
    "phoneNumber":"13111111111",
    "ip":"127.0.0.1",
    "nameCn":"法人姓名",
    "nameEn":"Legal Rep",
    "dateOfBirth":1514736000,
    "address":{
      "city":"北京",
      "country":"CN",
      "postalCode":"210000",
      "street1":"东四北大街107号",
      "street2":"克林大厦107室"},
    "idNumber":"432524199902287897",
    "idDoc":null,
    "merchantIds":[{
    "merchantId":"AAAAAAAAAAA",
    "merchantType":"Amazon"}],
    "expectedMonthlySales":40000,
    "shopName":"MyBrand",
    "website":"https://merchant.website.com",
    "repAaddress":{
      "city":"北京",
      "country":"CN",
      "postalCode":"210000",
      "street1":"东四北大街107号",
      "street2":"克林大厦107室"},
    "companyNameCn":"ABC有限责任公司",
    "companyNameEn":"ABC Company Limited",
    "registrationNumber":"123456789",
    "coiDoc":null,
    "salesDoc":null,
    "dateOfEstablishment":1514736000,
    "beneficialOwners":[{
      "fullName":"Richard",
      "idNumber":"1231321312",
      "idDoc":null}]
      }
    }
```


Once a new user requests a VBA via your platform, [create a wallet](#wallets) for that user.


Note:


1.You should collect the required documentation and pass through to us through this endpoint. The data is used for KYC purposes and is necessary in order to open the virtual banking facilities. The wallet will be opened immediately, and the banking information will be appended to the account once approved (after step 3)

2.Each wallet will automatically be assigned a walletId.

3.Take note of the `walletId` that gets generated in the response as this will be used later to manage the VBA.



### Step 2. Upload KYC documents


`POST` https://api.testwyre.com/v2/documents


VBA Wallets require the below documentation in order to be issued with a Virtual Bank `accountNumber`. When you upload a document using this endpoint you will receive a `documentId` which you will need for Step 3.


When updating pass the following parameters along with the URL:


Field |
--------- |
ownerSrn: "wallet:[WALLET_ID]" |
filename (optional): "coiDoc.pdf" |


E.g. `POST` https://api.testwyre.com/v2/documents?ownerSrn=wallet:WA-123123123&filename=coiDoc.pdf


In the body of the request simply include the raw bytes of file to be uploaded.


```java
public static String computeSignature2(String secretKey,String url, byte[] reqData) throws UnsupportedEncodingException {

       byte[] urlBytes = url.getBytes("UTF-8");

       byte[] data = new byte[urlBytes.length+reqData.length];

       System.arraycopy(urlBytes,0,data,0,urlBytes.length);
       System.arraycopy(reqData,0,data,urlBytes.length,reqData.length);

       try {
           Mac sha256Hmac = Mac.getInstance("HmacSHA256");
           SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
           sha256Hmac.init(key);

           byte[] macData = sha256Hmac.doFinal(data);

           StringBuffer result = new StringBuffer();
           for (final byte element : macData){
               result.append(Integer.toString((element & 0xff) + 0x100, 16).substring(1));
           }
           return result.toString();

       } catch (Exception e) {
           e.printStackTrace();
           return "";
       }
   }
```


Finally, the content-type header should reflect the file type - allowed content-types include:


Content Type |
--------- |
"application/msword" |
"application/vnd.openxmlformats-officedocument.wordprocessingml.document" |
"application/pdf" |
"image/jpg" |
"image/jpeg" |
"image/png" |


<br>
Once the file is uploaded the user will receive a "document" object as the response. Take the ID from this (e.g. DO-123123123) and provide it in the coiDoc, idDoc or salesDoc fields.


Field | Description
--------- | -----------
idDoc | A government-issued identity document such as a passport or national ID card.
coiDoc | The company's Certificate of Incorporation.
salesDoc | A document detailing the merchant's recent sales*


For Amazon - please use the ListFinancialEventsGroup query for the last 90 days to upload a xml file.



### Step 3. Update KYC Data to include documents

When documents are uploaded they are associated to the wallet according to the ownerSrn. In order to determine the type and the latest documents, please update the following fields in the `vbaVerificationData`:


<pre class="center-column">
{
  "vbaVerificationData":{
    "coiDoc":"DO-123123123",
    "idDoc":"DO-123123124",
    "salesDoc":"DO-123123125"
  }
}
</pre>


<br>
### Step 4. Check for banking data

Banking data is added as an `object` to the `vbaData` section of the wallet object.


<pre class="center-column">
{   
  "vbaData": {
    "bankName":"Evolve Bank & Trust",
    "bankAddress": "6070 Poplar Ave #100, Memphis TN 38119",
    "beneficiaryName":"Zhang San",
    "bankAccountNumber":"123123123",
    "routingNumber":"084106768"}
  }
</pre>


<br>
Query the wallet using `GET` https://api.testwyre.com/v2/wallet/[walletID]. Limit your queries to once per hour and once the data is added turn off the queries. In the future we will add a Callback for this event.


Once received you can now pass this information to your user to update their settlement information with their merchant platform.


### Step 5. Receiving Funds and Callbacks

Whenever we receive a payment to the `accountNumber`, once approved (note: payments from unapproved platforms will be rejected) a callback will be sent if you have set up a `callbackUrl`.


See [Callbacks](#callbacks).


If you wish to validate the callback you can use the `id` to `GET` the necessary information. For transfers within our system the id will belong to a transfer (e.g. TF-123123123) and you can query:

*https://api.testwyre.com/v2/transfer/[id]*

For the initial funding transation from outside our system (such as Amazon) the id will belong to a transaction (e.g. TR-123123123) and you can query:

*https://api.testwyre.com/v2/transaction/[id]*

<br>
**Result Format**

<pre class="center-column">
{
  "createdAt":1531445525097,
  "id":"TR-F3947W8C2C6",
  "source":"transfer:TF-HP4A42EC6DX",
  "dest":"wallet:WA-CF9RFZ7QU6W",
  "currency":"USD",
  "amount":5005.00,
  "status":"CONFIRMED",
  "confirmedAt":1531445525097,
  "cancelledAt":null,
  "reversedAt":null,
  "message":"Deposit for transfer TF-HP4A42EC6DX",
  "allowOverdraft":true,
  "authorizer":"account:AC-XXXXXXXXX",
  "senderProvidedId":null,
  "reversedBy":null,
  "fees":0,
  "feesDest":null,
  "metadata":{
    "Description":"Pending: Transfer of $5005.00 to wallet:WA-CF9RFZ7QU6W",
    "transferId":"TF-HP4A42EC6DX"},
    "tags":[],
    "sourceFees":null,
    "destFees":null
  }
</pre>


<br>

### Step 6. Transfer USD from wallet to Account


`POST` https://api.testwyre.com/v2/transfers


<pre class="center-column">
{
"source": "wallet:walletId",
"dest": "account:accountId",
"sourceCurrency": "USD",
"destCurrency": "USD",
"destAmount": 1000,
"autoConfirm": "true",
"message":"Merchant Test"
}
</pre>


Your account ID can be found [here](https://www.testwyre.com/settings/basic-info).


Then transfer USD from the Account to your pre-arranged Settlement Account (note: during setup - epiapi will create this Settlement Account as a `paymentMethod`)


<pre class="center-column">
{
"source": "account:accountId",
"dest": "paymentMethod:paymentMethodId",
"sourceCurrency": "USD",
"destCurrency": "USD",
"sourceAmount": 1000,
"amountIncludesFees": "true",
"autoConfirm": "true",
"message":"Merchant Test"
}
</pre>


Set `autoConfirm` to "true" to automatically confirm the transfer.


# Account


## Account Details

This endpoint retrieves all the information related to your account.


**Definition**

`GET` https://api.testwyre.com/v2/account


When checking your balance you should refer to the `availableBalance` object to see how much of a given currency you have available to transfer.


Field | Description
--------- | -----------
ID | An internal id corresponding to your account.
createdAt | Time at which the account was created.
updatedAt | The last time the account was updated.
loginAt | The last time the account was logged in to.
rank | The account's rank. Used for things like limits on the accounts option to purchase digital currencies.
profile | A set of fields that the user has permission to modify.
paymentMethods | A list of payment methods available on the account.
identities |  An array of identities (cellphone numbers, email addresses) associated with the account. Each identity includes information about when they were created and when they were verified.
depositAddresses | A map of digital currency deposit addresses for the account.
totalBalances | A map of the total amount of funds in the user's account. This is the sum of the pending balances and the available balances.
availableBalances | A map of the total amount of funds available to be withdrawn immediately from the account. If you are performing a check to see if the account has sufficient funds before making a withdrawal, you should check this balance.
email | The email tied to the account.
cellphone | The cellphone number tied to the account.


<br>
**Result Format**

<pre class="center-column">
{
  "id": "121pd02kt0rnb24nclsg4bglanimurqp",
  "createdAt": 1404177262332,
  "updatedAt": 1404177262332,
  "loginAt": 1404177262332,
  "rank": 0,
  "profile": {
    "firstName": "",
    "lastName": "",
    "locale": "EN_us",
    "address": {
      "street1": null,
      "street2": null,
      "city": null,
      "state": null,
      "postalCode": null,
      "country": "USA"
    },
    "businessAccount": true,
    "taxId": null,
    "doingBusinessAs": null,
    "website": null,
    "dateOfBirth": 1404177262332,
    "notifyEmail": true,
    "notifyCellphone": true,
    "notifyApnsDevice": true,
    "mfaRequiredForPwChange": false,
    "mfaRequiredForDcPurchase": false,
    "mfaRequiredForSendingFunds": false,
    "authyPhoneNumber": null
  },
  "paymentMethods": [],
  "identities": [
    {
      "srn": "email:richard@apiepi.com",
      "createdAt": 1404177262332,
      "verifiedAt": 1404177262332
    }
  ],
  "depositAddresses": {
    "BTC": "1H9K67J9NcYtzmFGojR9cgM5ybxEddySwu"
  },
  "totalBalances": {
    "USD": 11.8934023
  },
  "availableBalances": {
    "USD": 10.8934023,
  },
  "email": "richard@apiepi.com",
  "cellphone": "+12312313112"
}
</pre>


# Wallets

Wallets are used by epiapi to represent individual Merchant accounts. For our Virtual Banking solution all wallets should be created with `type=VBA`. The below shows a typical wallet-account flow.



![Flow-En.png](./Flow-En.png)



## Create Wallet


```cURL
curl -v -XPOST 'https://api.testwyre.com/v2/wallets' \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: {api-key}" \
  -H "X-Api-Signature: {signature}" \
  -d '{"type":"ENTERPRISE","name":"{your-unique-identifier}",
  "callbackUrl":"https://your.website.io/callback",
  "notes":"Notes about the sub account"}'
 ```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.Integer;
import java.lang.String;
import java.lang.StringBuffer;
import java.net.HttpURLConnection;
import java.net.URL;

public class Main {
  public static void main(String[] args) {
    String accountId = "k3f48j0rb2rp65c0sdog67vi43u80jas";
    String apiKey = "fll36l3t35udalcqlh4ng6bm4qpbgher";
    String secretKey = "tr3epinbk3maist0n3ijk18bm6dikrq6";

    String url = "https://api.testwyre.com/v2/wallets";
    String method = "POST";
    String data = "";

    String result = excuteWyereRequest(url, "", method, apiKey, secretKey);
    System.out.println(result);

    data = "{" +
        "  \"type\":\"ENTERPRISE\"," +
        "  \"name\":\"{your-unique-identifier}\"," +
        "  \"callbackUrl\":\"https://your.website.io/callback\"," +
        "  \"notes\":\"Notes about the user\"," +
        "  \"verificationData\": {" +
        "      \"firstName\":\"{users-first-name}\"," +
        "      \"middleName\":\"{users-middle-name}\"," +
        "      \"lastName\":\"{users-last-name}\"," +
        "      \"ssn\":\"0000\"," +
        "      \"passport\":\"123456\"," +
        "      \"birthDay\":\"1\"," +
        "      \"birthMonth\":\"1\"," +
        "      \"birthYear\":\"1970\"," +
        "      \"phoneNumber\":\"+15555555555\"," +
        "      \"address\": {" +
        "          \"street1\":\"1 Market Street\"," +
        "          \"street2\":\"Suit 420\"," +
        "          \"city\":\"San Francisco\"," +
        "          \"state\":\"CA\"," +
        "          \"postalCode\":\"94105\"," +
        "          \"country\":\"US\"" +
        "      }" +
        "  }" +
        "}";
    result = excuteWyreRequest(url, data, method, apiKey, secretKey);

    System.out.println(result);
  }

  public static String excuteWyreRequest(String targetURL, String requestBody, String method, String apiKey, String secretKey) {
    URL url;
    HttpURLConnection connection = null;
    try {

      targetURL += ((targetURL.indexOf("?")>0)?"&":"?") + "timestamp=" + System.currentTimeMillis();

      //Create connection
      url = new URL(targetURL);
      connection = (HttpURLConnection)url.openConnection();
      connection.setRequestMethod(method);
      System.out.println(connection.getRequestMethod());

      connection.setRequestProperty("Content-Type", "application/json");
      connection.setRequestProperty("Content-Length", Integer.toString(requestBody.getBytes().length));

      //Specify API v2
      connection.setRequestProperty("X-Api-Version","2");

      // Provide API key and signature
      connection.setRequestProperty("X-Api-Key", apiKey);
      connection.setRequestProperty("X-Api-Signature",computeSignature(secretKey,targetURL,requestBody));

      //Send request
      if(method.equals("POST")) {
        connection.setDoOutput(true);
        connection.setRequestMethod(method);

        DataOutputStream wr = new DataOutputStream(
            connection.getOutputStream());

        wr.writeBytes(requestBody);
        wr.flush();
        wr.close();
      }

      //Get Response
      InputStream is = connection.getInputStream();
      BufferedReader rd = new BufferedReader(new InputStreamReader(is));
      String line;
      StringBuffer response = new StringBuffer();
      while((line = rd.readLine()) != null) {
        response.append(line);
        response.append('\r');
      }
      rd.close();
      return response.toString();

    } catch (Exception e) {

      e.printStackTrace();
      return null;

    } finally {

      if(connection != null) {
        connection.disconnect();
      }
    }
  }

  public static String computeSignature(String secretKey, String url, String reqData) {

    String data = url + reqData;

    System.out.println(data);

    try {
      Mac sha256Hmac = Mac.getInstance("HmacSHA256");
      SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
      sha256Hmac.init(key);

      byte[] macData = sha256Hmac.doFinal(data.getBytes());

      String result = "";
      for (final byte element : macData){
        result += Integer.toString((element & 0xff) + 0x100, 16).substring(1);
      }
      return result;

    } catch (Exception e) {
      e.printStackTrace();
      return "";
    }
  }
}
```

```python
#dependencies:
#python3
#pip3 install requests

import json
import hmac
import time
from requests import request

class MassPay_API(object):
    def __init__(self, account_id, api_version, api_key, api_secret):
        self.account_id = account_id
        self.api_url = 'https://api.testwyre.com/{}'.format(api_version)
        self.api_version = api_version
        self.api_key = api_key
        self.api_secret = api_secret

    #authentication decorator. May raise ValueError if no json content is returned
    def authenticate_request(func):
        def wrap(self, *args, **kwargs):
            url, method, body = func(self, *args, **kwargs)
            params = {}
            timestamp = int(time.time() * 1000)
            url += '?timestamp={}'.format(timestamp)
            bodyJson = json.dumps(body) if body != '' else ''
            headers = {}
            headers['Content-Type'] = 'application/json'
            headers['X-Api-Version'] = self.api_version
            headers['X-Api-Key'] = self.api_key
            headers['X-Api-Signature'] = hmac.new(self.api_secret.encode('utf-8'), (url + bodyJson).encode('utf-8'), 'SHA256').hexdigest()
            print(headers['X-Api-Signature'])
            resp = request(method=method, url=url, params=params, data=(json.dumps(body) if body != '' else None), json=None, headers=headers)
            if resp.text is not None: #Wyre will always try to give an err body
                return resp.status_code, resp.json()
            return 404, {}
        return wrap

    @authenticate_request
    def create_user(self, name, callbackUrl, notes, verificationData):
        url = self.api_url + '/wallets'
        method = 'POST'
        body = {'name':name,
                'verificationData':verificationData,
                'type':'ENTERPRISE'}
        if callbackUrl:
            body["callbackUrl"] = callbackUrl
        if notes:
            body['notes'] = notes
        return url, method, body

#USAGE Example
account_id = "YOUR_ACCOUNT_ID_HERE" #optional
api_key = "YOUR_API_KEY_HERE"
secret_key = "YOUR_SECRET_KEY_HERE"
api_version = "2"

#create Wyre MassPay API object
Wyre = MassPay_API(account_id, api_version, api_key, secret_key)

#create user and print result
http_code, result = Wyre.create_user(
                                "{your-unique-identifier}",
                                "https://your.website.io/callback",
                                None, #notes
                                {
                                  "firstName": "{users-first-name}",
                                  "middleName": "{users-middle-name}",
                                  "lastName": "{users-last-name}",
                                  "ssn": "0000",
                                  "passport": "123456",
                                  "birthDay": "1",
                                  "birthMonth": "1",
                                  "birthYear": "1970",
                                  "phoneNumber": "+15555555555",
                                  "address": {
                                    "street1":"1 Market Street",
                                    "street2":"Suite 420",
                                    "city":"San Francisco",
                                    "state":"CA",
                                    "postalCode":"94105",
                                    "country":"US"
                                  }
                                })
print(result)
users_srn = result['srn'] #grab our srn identifier for the user
'''

'''php
<?php
    function make_authenticated_request($endpoint, $method, $body) {
        $url = 'https://api.testwyre.com';
        $api_key = "bh405n7stsuo5ut30iftrsl71b4iqjnv";
        $secret_key = "a19cvrchgja82urvn47kirrlrrb7stgg";

        $timestamp = floor(microtime(true)*1000);
        $request_url = $url . $endpoint;

        if(strpos($request_url,"?"))
            $request_url .= '&timestamp=' . $timestamp;
        else
            $request_url .= '?timestamp=' . $timestamp;

        if(!empty($body))
            $body = json_encode($body, JSON_FORCE_OBJECT);
        else
            $body = '';

        $headers = array(
            "Content-Type: application/json",
            "X-Api-Key: ". $api_key,
            "X-Api-Signature: ". calc_auth_sig_hash($secret_key, $request_url . $body),
            "X-Api-Version: 2"
        );
        $curl = curl_init();

        if($method=="POST"){
          $options = array(
            CURLOPT_URL             => $request_url,
            CURLOPT_POST            =>  true,
            CURLOPT_POSTFIELDS      => $body,
            CURLOPT_RETURNTRANSFER  => true);
        }else {
          $options = array(
            CURLOPT_URL             => $request_url,
            CURLOPT_RETURNTRANSFER  => true);
        }
        curl_setopt_array($curl, $options);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        $result = curl_exec($curl);
        curl_close($curl);
        var_dump($result);
        return json_decode($result, true);
    }

    function calc_auth_sig_hash($seckey, $val) {
        $hash = hash_hmac('sha256', $val, $seckey);
        return $hash;
    }

    $userData = array(
      "type"=>"ENTERPRISE",
      "name"=>"{your-unique-identifier}",
      "callbackUrl"=>"https://your.website.io/callback",
      "notes"=> "Notes about the user",
      "verificationData"=> array(
          "firstName"=> "{users-first-name}",
          "middleName"=> "{users-middle-name}",
          "lastName"=> "{users-last-name}",
          "ssn"=> "0000",
          "passport"=> "12345",
          "birthDay"=> "1",
          "birthMonth"=> "1",
          "birthYear"=> "1970",
          "phoneNumber"=> "+15555555555",
          "address"=> array(
            "street1":"1 Market Street",
            "street2":"Suite 420",
            "city":"San Francisco",
            "state":"CA",
            "postalCode":"94105",
            "country":"US"
          )
        )
      );
    echo make_authenticated_request("/wallets", "POST", $userData);
?>
```

**Definition**


`POST` https://api.testwyre.com/v2/wallets


**Parameters**


Param | Type | Description | Required
--------- | ----------- | ----------- | -----------
name | string | Unique identifier for the user | yes
callbackUrl | string | Callback url we will make HTTP postbacks to on wallet updates | no
type | string | The type of wallet you are creating; defaults to `DEFAULT` | no
notes | string | Notes about the user | no


<br>
**Result Format**

<pre class="center-column">
{
  "name" : "{your-unique-identifier}",
  "id" : "WA-AYBNA3lBiWAM4l3",
  "depositAddresses" : {
    "BTC" : "2ShL7kzSNNxedit6hC2fjSQhVcAucTeS1m7"
  },
  "totalBalances" : {
    "BTC" : 0
  },
  "availableBalances" : {
    "BTC" : 0
  },
  "srn" : "wallet:AYBNA3lBiWAM4l3",
  "balances" : {
    "BTC" : 0
  },
  "callbackUrl" : "https://your.website.io/callback",
  "notes" : "Notes about the user"
}
</pre>


<br>

## Create Mulitple Wallets

```cURL

curl -XPOST 'https://api.testwyre.com/v2/wallets/batch?pretty' \
-H 'Content-Type:application/json' \
-d '{
  "wallets":[
    {"name":"walletOne"},
    {"name":"walletTwo"},
    {"name":"walletThree"}
  ]
}'
```


This endpoint allows you to creates a batch of child wallets (1 child wallet/user) in one request.


**Definition**


`POST` https://api.testwyre.com/v2/wallets/batch


**Parameters**


Param | Type | Description | Required
--------- | ----------- | ----------- | -----------
wallets | array | array of wallet creation objects | yes

<br>
**Result Format**

<pre class="center-column">
{
  "name" : "walletOne",
  "id" : "AxVA57edP0H33x3",
  "notes" : null,
  "srn" : "wallet:AxVA57edP0H33x3",
  "callbackUrl" : null,
  "verificationData" : null,
  "depositAddresses" : {
    "BTC" : "2ShKKFb9gEP5uvRXtMbs7ykJAMPgoSSnSWB"
  },
  "totalBalances" : {
    "BTC" : 0
  },
  "availableBalances" : {
    "BTC" : 0
  },
  "balances" : {
    "BTC" : 0
  }
}, {
  "name" : "walletTwo",
  "id" : "AtEhoXje3C1V5zq",
  "notes" : null,
  "srn" : "wallet:AtEhoXje3C1V5zq",
  "callbackUrl" : null,
  "verificationData" : null,
  "depositAddresses" : {
    "BTC" : "2ShKndBJNHvzABhBzLxvfzzD2vt64C36dPc"
  },
  "totalBalances" : {
    "BTC" : 0
  },
  "availableBalances" : {
    "BTC" : 0
  },
  "balances" : {
    "BTC" : 0
  }
}, {
  "name" : "walletThree",
  "id" : "U07tSKMvofeMmx0",
  "notes" : null,
  "srn" : "wallet:U07tSKMvofeMmx0",
  "callbackUrl" : null,
  "verificationData" : null,
  "depositAddresses" : {
    "BTC" : "2ShJsBPUb4HrNtgaNZk3YQSi2ynpZ5YY7sT"
  },
  "totalBalances" : {
    "BTC" : 0

  },
  "availableBalances" : {
    "BTC" : 0
  },
  "balances" : {
    "BTC" : 0
  }
}
</pre>

## Lookup Wallet

**Lookup by user ID:**


```cURL
curl -v -XGET 'https://api.testwyre.com/v2/wallet/{wallet-id}' \
  -H "X-Api-Key: {api-key}" \
  -H "X-Api-Signature: {signature}" \
```


**Lookup by user name:**


```cURL
curl -v -XGET 'https://api.testwyre.com/v2/wallet' \
  -H "X-Api-Key: {api-key}" \
  -H "X-Api-Signature: {signature}" \
  -d name={your-identifier}
```


This endpoint allows you to look up the balance of a child wallet by ID or name.


<br>
**Definition**


`GET` https://api.testwyre.com/v2/wallet/{walletId}


**Parameters**


Param | Type | Description | Required
--------- | ----------- | ----------- | -----------
walletId | string | ID of the wallet | yes

<br>
**Definition**


`GET` https://api.testwyre.com/v2/wallet/


**Parameters**


Param | Type | Description | Required
--------- | ----------- | ----------- | -----------
name | string | name of the wallet | yes

<br>
**Results Format**

<pre class="center-column">
{
   "owner": "account:[account-ID]",
   "callbackUrl": null,
   "depositAddresses": {
       "BTC": "1FNAkNVt3gXdS3PZ1tDvetbcafKPsJPQTG"
   },
   "totalBalances": {
       "USD": 4.96
   },
   "availableBalances": {
       "USD": 4.96
   },
   "verificationData": null,
   "balances": {
       "USD": 4.96
   },
   "srn": "wallet:[Wallet-ID]",
   "createdAt": 1497861843000,
   "notes": "test1",
   "name": "richard",
   "id": "[Wallet-ID]"
}
</pre>


<br>


## Edit Wallet

```cURL
curl -v -XPOST 'https://api.testwyre.com/v2/wallet/{wallet-id}/update' \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: {api-key}" \
  -H "X-Api-Signature: {signature}" \
  -d '{"name":"{your-unique-identifier}","notes":"Updated notes about the sub account"}'
```

```python
#dependencies:
#python3
#pip3 install requests

import json
import hmac
import time
from requests import request

class MassPay_API(object):
    def __init__(self, account_id, api_version, api_key, api_secret):
        self.account_id = account_id
        self.api_url = 'https://api.testwyre.com/{}'.format(api_version)
        self.api_version = api_version
        self.api_key = api_key
        self.api_secret = api_secret

    #authentication decorator. May raise ValueError if no json content is returned
    def authenticate_request(func):
        def wrap(self, *args, **kwargs):
            url, method, body = func(self, *args, **kwargs)
            params = {}
            timestamp = int(time.time() * 1000)
            url += '?timestamp={}'.format(timestamp)
            bodyJson = json.dumps(body) if body != '' else ''
            headers = {}
            headers['Content-Type'] = 'application/json'
            headers['X-Api-Version'] = self.api_version
            headers['X-Api-Key'] = self.api_key
            headers['X-Api-Signature'] = hmac.new(self.api_secret.encode('utf-8'), (url + bodyJson).encode('utf-8'), 'SHA256').hexdigest()
            print(headers['X-Api-Signature'])
            resp = request(method=method, url=url, params=params, data=(json.dumps(body) if body != '' else None), json=None, headers=headers)
            if resp.text is not None: #Wyre will always try to give an err body
                return resp.status_code, resp.json()
            return 404, {}
        return wrap

    @authenticate_request
    def update_user(self, walletId, name, callbackUrl, notes, verificationData):
        url = self.api_url + '/wallet/' + walletId + '/update'
        method = 'POST'
        body = {'name':name}
        if callbackUrl:
            body["callbackUrl"] = callbackUrl
        if notes:
            body['notes'] = notes
        if verificationData:
            body['verificationData'] = verificationData
        return url, method, body

#USAGE Example
account_id = "YOUR_ACCOUNT_ID_HERE" #optional
api_key = "YOUR_API_KEY_HERE"
secret_key = "YOUR_SECRET_KEY_HERE"
api_version = "2"

#create Wyre MassPay API object
Wyre = MassPay_API(account_id, api_version, api_key, secret_key)

#create user and print result
http_code, result = Wyre.update_user(
                                "{wallet-id}",
                                "{your-unique-identifier}",
                                None, #callbackUrl
                                "Updated notes for user",
                                None #verification data
                                )
print(result)
users_srn = result['srn'] #grab our srn identifier for the user
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.Integer;
import java.lang.String;
import java.lang.StringBuffer;
import java.net.HttpURLConnection;
import java.net.URL;

public class Main {
  public static void main(String[] args) {
    String accountId = "k3f48j0rb2rp65c0sdog67vi43u80jas";
    String apiKey = "fll36l3t35udalcqlh4ng6bm4qpbgher";
    String secretKey = "tr3epinbk3maist0n3ijk18bm6dikrq6";

    String walletId = "{wallet-id}";

    String url = "https://api.testwyre.com/v2/wallet/"+ walletId +"/update";
    String method = "POST";
    String data = "";

    String result = excuteWyreRequest(url, "", method, apiKey, secretKey);
    System.out.println(result);

    data = "{" +
        "  \"name\":\"{your-unique-identifier}\"," +
        "  \"notes\":\"Updated notes about the user\"" +
        "}";
    result = excuteWyreRequest(url, data, method, apiKey, secretKey);

    System.out.println(result);
  }

  public static String excuteWyreRequest(String targetURL, String requestBody, String method, String apiKey, String secretKey) {
    URL url;
    HttpURLConnection connection = null;
    try {

      targetURL += ((targetURL.indexOf("?")>0)?"&":"?") + "timestamp=" + System.currentTimeMillis();

      //Create connection
      url = new URL(targetURL);
      connection = (HttpURLConnection)url.openConnection();
      connection.setRequestMethod(method);
      System.out.println(connection.getRequestMethod());

      connection.setRequestProperty("Content-Type", "application/json");
      connection.setRequestProperty("Content-Length", Integer.toString(requestBody.getBytes().length));

      //Specify API v2
      connection.setRequestProperty("X-Api-Version","2");

      // Provide API key and signature
      connection.setRequestProperty("X-Api-Key", apiKey);
      connection.setRequestProperty("X-Api-Signature",computeSignature(secretKey,targetURL,requestBody));

      //Send request
      if(method.equals("POST")) {
        connection.setDoOutput(true);
        connection.setRequestMethod(method);

        DataOutputStream wr = new DataOutputStream(
            connection.getOutputStream());

        wr.writeBytes(requestBody);
        wr.flush();
        wr.close();
      }

      //Get Response
      InputStream is = connection.getInputStream();
      BufferedReader rd = new BufferedReader(new InputStreamReader(is));
      String line;
      StringBuffer response = new StringBuffer();
      while((line = rd.readLine()) != null) {
        response.append(line);
        response.append('\r');
      }
      rd.close();
      return response.toString();

    } catch (Exception e) {

      e.printStackTrace();
      return null;

    } finally {

      if(connection != null) {
        connection.disconnect();
      }
    }
  }

  public static String computeSignature(String secretKey, String url, String reqData) {

    String data = url + reqData;

    System.out.println(data);

    try {
      Mac sha256Hmac = Mac.getInstance("HmacSHA256");
      SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
      sha256Hmac.init(key);

      byte[] macData = sha256Hmac.doFinal(data.getBytes());

      String result = "";
      for (final byte element : macData){
        result += Integer.toString((element & 0xff) + 0x100, 16).substring(1);
      }
      return result;

    } catch (Exception e) {
      e.printStackTrace();
      return "";
    }
  }
}
```


This endpoint updates the information for a accounts child wallet.


**Definition**


`POST` https://api.testwyre.com/v2/wallet/{walletId}


## Delete Wallet


```cURL

curl -v -XDELETE 'https://api.testwyre.com/v2/wallet/{wallet-id}' \
  -H "X-Api-Key: {api-key}" \
  -H "X-Api-Signature: {signature}"
```


This endpoint removes the wallet from your account. Note that the wallet data is retained in our system for compliance purposes. Once an account is deleted the Virtual Bank Account associated with the wallet will be closed and no longer availabel for receiving funds.


**Definition**


`DELETE` https://api.testwyre.com/v2/wallet/{walletId}


**Parameters**


Param | Type | Description | Required
--------- | ----------- | ----------- | -----------
walletId | string | ID of the wallet | yes


## List Wallets


This endpoint will return all the child wallets you have created.


**Definition**


`GET` https://api.testwyre.com/v2/wallets


**Parameters**


Param | Type | Description | Required
--------- | ----------- | ----------- | -----------
limit | string | The number of results returned | yes
offset | string | The number of records to skip | yes

<br>
**Result Format**

<pre class="center-column">
{
  "data": {
      "owner": "account:XAV3CRAC94P",
      "balances": {},
      "srn": "wallet:WA-XM4L3JMUQGF",
      "createdAt": 1508433396000,
      "callbackUrl": "https://shake.webscript.io/callback",
      "depositAddresses": {
        "BTC": "1Q9TqsVwuZf6bYqtxxjqdataXx81x3Q1h7"
      },
      "totalBalances": {},
      "availableBalances": {},
      "notes": "nope",
      "name": "Person A",
      "id": "WA-XM4L3JMUQGF"
     }
  }
</pre>

# Transfers

## Introduction


Transfers represent the building blocks of our API. Our Transfer API is an incredibly versatile way of moving funds not only externally but internally as well, whether it's through internal account management or internal exchanges.  Additionally, you can specify differing source and destination currencies and the funds will automatically exchanged into the appropriate currency in our backend.


Anytime you want to move funds around on the platform you will create a Transfer. The Transfer will go through a number of states as funds are moved to the destination of your choice.



## Create Transfer


**Definition**


`POST` https://api.testwyre.com/v2/transfer/


This endpoint creates a new money transfer.



<pre class="center-column">
{  
   "source":"account:AC-123123123",
   "sourceCurrency":"USD",
   "sourceAmount":"5",
   "dest":"email:sam@testwyre.com",
   "destCurrency":"CNY",
   "message": ""
}
</pre>




**Parameters**


Param | Type | Description | required
--------- | ----------- | ----------- | -----------
source | string | An SRN representing an account that the funds will be retrieved from. | no
sourceAmount | double | The amount to withdrawal from the source, in units of `sourceCurrency`. Only include `sourceAmount` OR `destAmount`, not both. | yes
sourceCurrency | string | An ISO 3166-1 alpha-3 currency code that will be deducted from your account. | yes
dest | string | An payment method, wallet to send the digital currency to. Note: cellphone numbers are assumed to be a US number, for international numbers include a '+' and the country code as the prefix. | yes
destAmount | double | Specifies the total amount of currency to deposit (as defined in depositCurrency). Only include `sourceAmount` OR `destAmount`, not both. | yes
destCurrency | string | An ISO 3166-1 alpha-3 currency code that matches the dest type. The destCurrency can be the same or different from the sourceCurrency. If they are different an exchange will automatically occur. | yes
message | string | An optional user visible message to be sent with the transaction. | no
callbackUrl | string | An optional url that Wyre will POST a status callback to. | no
autoConfirm | boolean | An optional parameter to automatically confirm the transfer order. | no
customId | string | An optional tag that must be unique for each transaction if used or transaction will fail. | no
amountIncludesFees | boolean | Optional- if true, the amount given (source, dest, equiv) will be treated as already including the fees and nothing in addition will be withdrew. | no
preview | boolean | If true, creates a quote transfer object, but does not execute a real transfer. | no
muteMessages | boolean | When true, disables outbound emails/messages to the destination. | no


<br>

Once you've created the transfer it will be in an UNCONFIRMED state. You will have 30 seconds to review the transfer and [confirm it](#confirm-transfer) before the quote expires. If the quote expires you'll have to reissue the transfer request and confirm the new transfer. However you can CONFIRM the transfer AUTOMATICALLY by setting `autoConfirm` to `true`.


When reviewing the transfer the main things you'll want to check out are the following:


`exchangeRate` - The quoted exchange rate for the transfer totalFees - The total fees will always be represented in the source currency. To convert totalFees to the destination currency, multiply totalFees by the exchange rate. Note that this object includes all epiapi fees.


`sourceAmount/destAmount` - Depending on the request you made, you'll want to double check these fields at this stage and make sure that you're either sending or receiving the amount you expected. Note the values for these fields depend on the amountIncludesFees parameter.

<br>
**Result Format**

<pre class="center-column">
{
    "id": "TF-VWGF3WW6JU4",
    "status": "PENDING",
    "failureReason": null,
    "language": "en",
    "createdAt": 1525196883000,
    "updatedAt": 1525196883000,
    "completedAt": 1525196884000,
    "cancelledAt": null,
    "expiresAt": 1525456083000,
    "owner": "account:AC-PJZEFT7JP6J",
    "source": "service:Fiat Credits",
    "dest": "wallet:WA-AFFGZJJ7X82",
    "sourceCurrency": "USD",
    "sourceAmount": 10,
    "destCurrency": "USD",
    "destAmount": 10,
    "exchangeRate": null,
    "message": null,
    "totalFees": 0,
    "fees": {
        "USD": 0
    },
    "customId": null,
    "reversingSubStatus": null,
    "reversalReason": null,
    "pendingSubStatus": null,
    "destName": "amandawallet",
    "sourceName": "Wyre",
    "blockchainTx": null,
    "statusHistories": [
        {
            "id": "HNUBAMZ4YQQ",
            "createdAt": 1525196884000,
            "statusDetail": "Initiating Transfer",
            "state": "INITIATED",
            "failedState": null
        },
        {
            "id": "V8L2MJNPF6D",
            "createdAt": 1525196884000,
            "statusDetail": "Transfer Pending",
            "state": "PENDING",
            "failedState": null
        }
    ]
}
</pre>


## Confirm Transfer


This endpoint confirms a money transfer. Once you've created the transfer and receive a 200 response, you will have 30 seconds to confirm the transfer. Note the `transferId` after you create the transfer. If you want to automatically confirm the transfer without making an additional API call, set parameter `autoConfirm` to "true" in your [Create Transfer](#create-transfer) request.


**Definition**


`POST` https://api.testwyre.com/v2/transfer/transferId:/confirm


**Parameters**


Param | Type | Description
--------- | ----------- | -----------
transferId | string | ID of the transfer to confirm

<br>
**Result Format**

<pre class="center-column">
{
    "id": "TF-VWGF3WW6JU4",
    "status": "COMPLETED",
    "failureReason": null,
    "language": "en",
    "createdAt": 1525196883000,
    "updatedAt": 1525196883000,
    "completedAt": 1525196884000,
    "cancelledAt": null,
    "expiresAt": 1525456083000,
    "owner": "account:AC-PJZEFT7JP6J",
    "source": "service:Fiat Credits",
    "dest": "wallet:WA-AFFGZJJ7X82",
    "sourceCurrency": "USD",
    "sourceAmount": 10,
    "destCurrency": "USD",
    "destAmount": 10,
    "exchangeRate": null,
    "message": null,
    "totalFees": 0,
    "fees": {
        "USD": 0
    },
    "customId": null,
    "reversingSubStatus": null,
    "reversalReason": null,
    "pendingSubStatus": null,
    "destName": "amandawallet",
    "sourceName": "Wyre",
    "blockchainTx": null,
    "statusHistories": [
        {
            "id": "HNUBAMZ4YQQ",
            "createdAt": 1525196884000,
            "statusDetail": "Initiating Transfer",
            "state": "INITIATED",
            "failedState": null
        },
        {
            "id": "V8L2MJNPF6D",
            "createdAt": 1525196884000,
            "statusDetail": "Transfer Completed",
            "state": "COMPLETED",
            "failedState": null
        }
    ]
}
</pre>


## Lookup Transfer

This endpoint allows you to look up information related to a transfer you already created.


**Definition**


`GET` https://api.testwyre.com/v2/transfer?customId=


**Parameters**


Param | Type | Description
--------- | ----------- | -----------
customId | string | The custom id you provided when creating the transfer
<br>

**Result Format**

<pre class="center-column">
{
    "id": "TF-VWGF3WW6JU4",
    "status": "COMPLETED",
    "failureReason": null,
    "language": "en",
    "createdAt": 1525196883000,
    "updatedAt": 1525196883000,
    "completedAt": 1525196884000,
    "cancelledAt": null,
    "expiresAt": 1525456083000,
    "owner": "account:AC-PJZEFT7JP6J",
    "source": "service:Fiat Credits",
    "dest": "wallet:WA-AFFGZJJ7X82",
    "sourceCurrency": "USD",
    "sourceAmount": 10,
    "destCurrency": "USD",
    "destAmount": 10,
    "exchangeRate": null,
    "message": null,
    "totalFees": 0,
    "fees": {
        "USD": 0
    },
    "customId": null,
    "reversingSubStatus": null,
    "reversalReason": null,
    "pendingSubStatus": null,
    "destName": "amandawallet",
    "sourceName": "Wyre",
    "blockchainTx": null,
    "statusHistories": [
        {
            "id": "HNUBAMZ4YQQ",
            "createdAt": 1525196884000,
            "statusDetail": "Initiating Transfer",
            "state": "INITIATED",
            "failedState": null
        },
        {
            "id": "V8L2MJNPF6D",
            "createdAt": 1525196884000,
            "statusDetail": "Transfer Completed",
            "state": "COMPLETED",
            "failedState": null
        }
    ]
}
</pre>


## Transfer Status


**Definition**


`GET` https://api.testwyre.com/v2/transfer/:transferId


**Parameters**


Param | Type | Description
--------- | ----------- | -----------
transferId | string | Wyre generated transferId

<br>
**Result Format**

<pre class="center-column">
{
    "id": "TF-VWGF3WW6JU4",
    "status": "COMPLETED",
    "failureReason": null,
    "language": "en",
    "createdAt": 1525196883000,
    "updatedAt": 1525196883000,
    "completedAt": 1525196884000,
    "cancelledAt": null,
    "expiresAt": 1525456083000,
    "owner": "account:AC-PJZEFT7JP6J",
    "source": "service:Fiat Credits",
    "dest": "wallet:WA-AFFGZJJ7X82",
    "sourceCurrency": "USD",
    "sourceAmount": 10,
    "destCurrency": "USD",
    "destAmount": 10,
    "exchangeRate": null,
    "message": null,
    "totalFees": 0,
    "fees": {
        "USD": 0
    },
    "customId": null,
    "reversingSubStatus": null,
    "reversalReason": null,
    "pendingSubStatus": null,
    "destName": "amandawallet",
    "sourceName": "Wyre",
    "blockchainTx": null,
    "statusHistories": [
        {
            "id": "HNUBAMZ4YQQ",
            "createdAt": 1525196884000,
            "statusDetail": "Initiating Transfer",
            "state": "INITIATED",
            "failedState": null
        },
        {
            "id": "V8L2MJNPF6D",
            "createdAt": 1525196884000,
            "statusDetail": "Transfer Completed",
            "state": "COMPLETED",
            "failedState": null
        }
    ]
}
</pre>



<br>

Once a Transfer enters the PENDING state we will start moving money to the destination account. At some point the Transfer will either move to a COMPLETED status or a FAILED status asynchronously from any API call.


## Callbacks

We provide a series of HTTP callbacks that allow you to notify users when funds have been deposited and when they become available.


**When callbacks are sent**


Callbacks are sent whenever a transactional event occurs that will affect the account's balance. Examples include:


* Incoming pending transaction
* Pending transaction confirmed
* Outgoing transaction


You may receive two callbacks for a single transaction. This is especially true for transactions on the blockchain. In these cases, you would receive one callback when the transaction is first observed and one callback once the transaction is confirmed.


**Callback Acceptance and Retries**


Your system should respond to the callback request with a 200 response. We only attempt to send the request once, but we may introduce automatic retries in the future. We can manually resend callbacks upon request.


<br>
**Result Format**

<pre class="center-column">
{
    "id": "TF-VWGF3WW6JU4",
    "status": "COMPLETED",
    "failureReason": null,
    "language": "en",
    "createdAt": 1525196883000,
    "updatedAt": 1525196883000,
    "completedAt": 1525196884000,
    "cancelledAt": null,
    "expiresAt": 1525456083000,
    "owner": "account:AC-PJZEFT7JP6J",
    "source": "service:Fiat Credits",
    "dest": "wallet:WA-AFFGZJJ7X82",
    "sourceCurrency": "USD",
    "sourceAmount": 10,
    "destCurrency": "USD",
    "destAmount": 10,
    "exchangeRate": null,
    "message": null,
    "totalFees": 0,
    "fees": {
        "USD": 0
    },
    "customId": null,
    "reversingSubStatus": null,
    "reversalReason": null,
    "pendingSubStatus": null,
    "destName": "amandawallet",
    "sourceName": "Wyre",
    "blockchainTx": null,
    "statusHistories": [
        {
            "id": "HNUBAMZ4YQQ",
            "createdAt": 1525196884000,
            "statusDetail": "Initiating Transfer",
            "state": "INITIATED",
            "failedState": null
        },
        {
            "id": "V8L2MJNPF6D",
            "createdAt": 1525196884000,
            "statusDetail": "Transfer Completed",
            "state": "COMPLETED",
            "failedState": null
        }
    ]
}
</pre>


<br>
The callback payload will be a JSON representation of the transaction that has caused the callback to trigger.


# Payment Methods

## Create Payment Method

```json
{
    "paymentMethodType":"INTERNATIONAL_TRANSFER",
    "country": "US",
    "currency": "USD",
    "beneficiaryType": "INDIVIDUAL",
    "beneficiaryAddress": "112 Brannan St",
    "beneficiaryAddress2": "", //Optional
    "beneficiaryCity": "San Francisco",
    "beneficiaryState": "CA",
    "beneficiaryPostal": "94108",
    "beneficiaryPhoneNumber": "+14102239203",
    "beneficiaryDobDay": "15",
    "beneficiaryDobMonth":"12",
    "beneficiaryDobYear":"1989",
    "paymentType" : "LOCAL_BANK_WIRE", // LOCAL_BANK_WIRE
    "firstNameOnAccount": "Billy-Bob",
    "lastNameOnAccount":"Jones",
    "accountNumber": "0000000000000",
    "routingNumber": "0000000000",
    "accountType": "CHECKING", //CHECKING or SAVINGS
    "chargeablePM": "true"
}
```


This is going to be your corporation's bank information.
We take this as a way to validate that they're the sender of the payment.
It allows us to know where to expect the payment to be coming from.


```json
{
    "paymentMethodType":"INTERNATIONAL_TRANSFER",
    "country": "US",
    "currency": "USD",
    "beneficiaryType": "CORPORATE",
    "beneficiaryCompanyName":"",
    "beneficiaryAddress": "112 Brannan St",
    "beneficiaryAddress2": "", //Optional
    "beneficiaryCity": "San Francisco",
    "beneficiaryState": "CA",
    "beneficiaryPostal": "94108",
    "beneficiaryLandlineNumber":"+123464542947",
    "beneficiaryEmailAddress":"tes@testwyre.com",
    "beneficiaryEinTin":"00000000",
    "beneficiaryDobDay": "15", //Date of Incorporation
    "beneficiaryDobMonth":"12", //Date of Incorporation
    "beneficiaryDobYear":"1989", //Date of Incorporation
    "paymentType" : "LOCAL_BANK_WIRE", // LOCAL_BANK_WIRE
    "accountType": "CHECKING", //CHECKING or SAVINGS
    "accountNumber": "0000000000000",
    "routingNumber": "0000000000",
    "chargeablePM": "true"
  }
```


This endpoint creates a bank account.

## Lookup Payment Method

This endpoint looks up the bank details associated with a payment method you created.


**Definition**


`GET` https://api.testwyre.com/v2/paymentMethod/:paymentMethodId

<br>
**Result Format**

<pre class="center-column">
{
    "id": "TestPaymentMethod",
    "owner": "account:ABCDEFG",
    "createdAt": 1230940800000,
    "name": "TEST PAYMENT METHOD",
    "defaultCurrency": "USD",
    "status": "ACTIVE",
    "statusMessage": null,
    "waitingPrompts": [],
    "linkType": "TEST",
    "supportsDeposit": true,
    "nameOnMethod": null,
    "last4Digits": null,
    "brand": null,
    "expirationDisplay": null,
    "countryCode": null,
    "nickname": null,
    "rejectionMessage": null,
    "disabled": false,
    "supportsPayment": true,
    "chargeableCurrencies": [
        "GBP",
        "MXN",
        "HKD",
        "USD",
        "CNY",
        "BRL",
        "EUR",
    ],
    "depositableCurrencies": [
        "USD"
    ],
    "chargeFeeSchedule": null,
    "depositFeeSchedule": null,
    "minCharge": null,
    "maxCharge": null,
    "minDeposit": null,
    "maxDeposit": null,
    "documents": [],
    "srn": "paymentmethod:TestPaymentMethod"
}
</pre>

## USD Payouts

USD payouts are initiated from one of our banks that corresponds to the country delivered. Please note that the minimum amount to transfer USD is $5.00.


**Definition**


`POST` https://api.testwyre.com/v2/transfers


```json
{
  "dest": {
    "paymentMethodType":"INTERNATIONAL_TRANSFER",
    "country": "US",
    "currency": "USD",
    "beneficiaryType": "INDIVIDUAL",
    "beneficiaryAddress": "112 Brannan St",
    "beneficiaryAddress2": "", //Optional
    "beneficiaryCity": "San Francisco",
    "beneficiaryState": "CA",
    "beneficiaryPostal": "94108",
    "beneficiaryPhoneNumber": "+14102239203",
    "beneficiaryDobDay": "15",
    "beneficiaryDobMonth":"12",
    "beneficiaryDobYear":"1989",
    "paymentType" : "LOCAL_BANK_WIRE",
    "firstNameOnAccount": "Billy-Bob",
    "lastNameOnAccount":"Jones",
    "accountNumber": "0000000000000",
    "routingNumber": "0000000000",
    "accountType": "CHECKING", // CHECKING or SAVINGS
    "bankName": "Bank of America"
  },
  "sourceCurrency": "BRL",
  "destCurrency": "USD",
  "destAmount": 10,
  "message":"USD Personal example"
}
```


**US Requirements**


Parameter | Description
--------- | -----------
dest | object
dest.paymentMethodType | `INTERNATIONAL_TRANSFER`
dest.country | US
dest.currency | USD
dest.beneficiaryType | `INDIVIDUAL` or `CORPORATE`
dest.beneficiaryPhoneNumber | Required for Individual
dest.beneficiaryLandlineNumber | Required for Business
dest.beneficiaryEinTin | Required for Business
dest.beneficiaryEmailAddress | Required for Business
dest.beneficiaryCompanyName | Required for Business
dest.firstNameOnAccount | Beneficiary's first name
dest.lastNameOnAccount | Beneficiary's last name
dest.accountNumber | Beneficiary account number
dest.routingNumber | Beneficiary routing number
dest.accountType | `CHECKING` or `SAVINGS`
destAmount | Amount to be deposited to the dest - the amount debited from your account will be calculated automatically from the exchange rate/fees.
destCurrency | Currency to be deposited to the dest. If destCurrency doesn't match the sourceCurrency an exchange will be performed
sourceCurrency | Currency to be debited from your account



- - - -


**Delivery Times**


Bank cut-off time is 4PM CT.


If we receive the payment instruction on the day before 4PM CT, the payment will be sent out that same day.-If we receive the payment instruction after 4PM CT, it will be credited to beneficiary next business day +1.
