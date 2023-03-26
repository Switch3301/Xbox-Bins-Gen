import time
import base64
import hashlib
import hmac
import secrets
import string
from threading import Lock
import random

thread_lock = Lock()

def generate_permission_data(data: str, secret: str) -> dict[str, str]:
    time_ms = int(time.time() * 1000)
    timeframe = time_ms // 36000 * 36000
    key_token = base64.urlsafe_b64encode(secret.encode()).decode()
    data_b64 = base64.urlsafe_b64encode(data.encode()).decode()
    pxmac = hmac.new(secret.encode(),
                      msg=f"PI|{data}|{timeframe}".encode(),
                      digestmod=hashlib.sha256).hexdigest().upper()
    return {"pxmac": pxmac, "keyToken": key_token, "data": data_b64}

def db64(data: bytes, altchars: bytes = b'+/') -> bytes:
    padding = b'=' * ((4 - len(data) % 4) % 4)
    data += padding
    return base64.b64decode(data, altchars)

def remove_content(filename: str, delete_line: str) -> None:
    with thread_lock, open(filename, "r+") as file:
        lines = file.readlines()
        file.seek(0)
        file.writelines(line for line in lines if delete_line not in line)
        file.truncate()

def getRandomLetters(length: int) -> str:
    return ''.join(secrets.choice(string.ascii_uppercase) for _ in range(length))

def generateHexStr(length: int) -> str:
    return secrets.token_hex(length//2)

def getRandomInt(length: int) -> str:
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def checkLuhn(cardNo):

	nDigits = len(cardNo)
	nSum = 0
	isSecond = False

	for i in range(nDigits - 1, -1, -1):
		d = ord(cardNo[i]) - ord('0')

		if (isSecond == True):
			d = d * 2
		nSum += d // 10
		nSum += d % 10

		isSecond = not isSecond

	if (nSum % 10 == 0):
		return True
	else:
		return False
	
def getValidCard(cardBin, binMonth, binYear, cvv):
	randDigitLen = 16 - len(cardBin)
	while True:
		UnchckCCN = cardBin + getRandomInt(randDigitLen)
		if checkLuhn(UnchckCCN):
			ccn = UnchckCCN
			break
		else:
			continue
	if binMonth == "rnd":
		mnth = str(random.randint(1, 12))
	else:
		mnth = binMonth
	if binYear == "rnd":
		year = str(random.randint(2022, 2030))
	else:
		year = binYear
	if cvv == "rnd":
		cvc = str(random.randint(000, 999))
	else:
		cvc = cvv
	full_card = f"{ccn}|{mnth}|{year}|{cvc}"
	return full_card