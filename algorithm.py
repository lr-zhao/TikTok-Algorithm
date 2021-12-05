import hashlib
from urllib import request, parse
import time
from io import StringIO
import gzip
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

byteTable1 = "D6 28 3B 71 70 76 BE 1B A4 FE 19 57 5E 6C BC 21 B2 14 37 7D 8C A2 FA 67 55 6A 95 E3 FA 67 78 ED 8E 55 33 89 A8 CE 36 B3 5C D6 B2 6F 96 C4 34 B9 6A EC 34 95 C4 FA 72 FF B8 42 8D FB EC 70 F0 85 46 D8 B2 A1 E0 CE AE 4B 7D AE A4 87 CE E3 AC 51 55 C4 36 AD FC C4 EA 97 70 6A 85 37 6A C8 68 FA FE B0 33 B9 67 7E CE E3 CC 86 D6 9F 76 74 89 E9 DA 9C 78 C5 95 AA B0 34 B3 F2 7D B2 A2 ED E0 B5 B6 88 95 D1 51 D6 9E 7D D1 C8 F9 B7 70 CC 9C B6 92 C5 FA DD 9F 28 DA C7 E0 CA 95 B2 DA 34 97 CE 74 FA 37 E9 7D C4 A2 37 FB FA F1 CF AA 89 7D 55 AE 87 BC F5 E9 6A C4 68 C7 FA 76 85 14 D0 D0 E5 CE FF 19 D6 E5 D6 CC F1 F4 6C E9 E7 89 B2 B7 AE 28 89 BE 5E DC 87 6C F7 51 F2 67 78 AE B3 4B A2 B3 21 3B 55 F8 B3 76 B2 CF B3 B3 FF B3 5E 71 7D FA FC FF A8 7D FE D8 9C 1B C4 6A F9 88 B5 E5"


def getXGon(url, stub, cookies):
    NULL_MD5_STRING = "00000000000000000000000000000000"
    sb = ""
    if len(url) < 1:
        sb = NULL_MD5_STRING
    else:
        sb = encryption(url)
    if len(stub) < 1:
        sb += NULL_MD5_STRING
    else:
        sb += stub
    if len(cookies) < 1:
        sb += NULL_MD5_STRING
    else:
        sb += encryption(cookies)
    index = cookies.index("sessionid=")
    if index == -1:
        sb += NULL_MD5_STRING
    else:
        sessionid = cookies[index + 10:]
        if sessionid.__contains__(';'):
            endIndex = sessionid.index(';')
            sessionid = sessionid[:endIndex]
        sb += encryption(sessionid)
    return sb


def encryption(url):
    obj = hashlib.md5()  # 先创建一个md5的对象
    # 写入要加密的字节
    obj.update(url.encode("UTF-8"))
    # 获取密文
    secret = obj.hexdigest()
    return secret.lower()


def initialize(data):
    myhex = 0
    byteTable2 = byteTable1.split(" ")
    for i in range(len(data)):
        hex1 = 0
        if i == 0:
            hex1 = int(byteTable2[int(byteTable2[0], 16) - 1], 16)
            byteTable2[i] = hex(hex1)
            # byteTable2[i] = Integer.toHexString(hex1);
        elif i == 1:
            temp = int("D6", 16) + int("28", 16)
            if temp > 256:
                temp -= 256
            hex1 = int(byteTable2[temp - 1], 16)
            myhex = temp
            byteTable2[i] = hex(hex1)
        else:
            temp = myhex + int(byteTable2[i], 16)
            if temp > 256:
                temp -= 256
            hex1 = int(byteTable2[temp - 1], 16)
            myhex = temp
            byteTable2[i] = hex(hex1)
        if hex1 * 2 > 256:
            hex1 = hex1 * 2 - 256
        else:
            hex1 = hex1 * 2
        hex2 = byteTable2[hex1 - 1]
        result = int(hex2, 16) ^ int(data[i], 16)
        data[i] = hex(result)
    for i in range(len(data)):
        data[i] = data[i].replace("0x", "")
    return data


def handle(data):
    for i in range(len(data)):
        byte1 = data[i]
        if len(byte1) < 2:
            byte1 += '0'
        else:
            byte1 = data[i][1] + data[i][0]
        if i < len(data) - 1:
            byte1 = hex(int(byte1, 16) ^ int(data[i + 1], 16)).replace("0x", "")
        else:
            byte1 = hex(int(byte1, 16) ^ int(data[0], 16)).replace("0x", "")
        byte1 = byte1.replace("0x", "")
        a = (int(byte1, 16) & int("AA", 16)) / 2
        a = int(abs(a))
        byte2 = ((int(byte1, 16) & int("55", 16)) * 2) | a
        byte2 = ((byte2 & int("33", 16)) * 4) | (int)((byte2 & int("cc", 16)) / 4)
        byte3 = hex(byte2).replace("0x", "")
        if len(byte3) > 1:
            byte3 = byte3[1] + byte3[0]
        else:
            byte3 += "0"
        byte4 = int(byte3, 16) ^ int("FF", 16);
        byte4 = byte4 ^ int("14", 16)
        data[i] = hex(byte4).replace("0x", "")
    return data


def xGorgon(timeMillis, inputBytes):
    data1 = []
    data1.append("3")
    data1.append("61")
    data1.append("41")
    data1.append("10")
    data1.append("80")
    data1.append("0")
    data2 = input(timeMillis, inputBytes)
    data2 = initialize(data2)
    data2 = handle(data2)
    for i in range(len(data2)):
        data1.append(data2[i])

    xGorgonStr = ""
    for i in range(len(data1)):
        temp = data1[i] + ""
        if len(temp) > 1:
            xGorgonStr += temp
        else:
            xGorgonStr += "0"
            xGorgonStr += temp
    return xGorgonStr


def input(timeMillis, inputBytes):
    result = []
    for i in range(4):
        if inputBytes[i] < 0:
            temp = hex(inputBytes[i]) + ''
            temp = temp[6:]
            result.append(temp)
        else:
            temp = hex(inputBytes[i]) + ''
            result.append(temp)
    for i in range(4):
        result.append("0")
    for i in range(4):
        if inputBytes[i + 32] < 0:
            result.append(hex(inputBytes[i + 32]) + '')[6:]
        else:
            result.append(hex(inputBytes[i + 32]) + '')
    for i in range(4):
        result.append("0")
    tempByte = hex(int(timeMillis)) + ""
    tempByte = tempByte.replace("0x", "")
    for i in range(4):
        a = tempByte[i * 2:2 * i + 2]
        result.append(tempByte[i * 2:2 * i + 2])
    for i in range(len(result)):
        result[i] = result[i].replace("0x", "")
    return result


def strToByte(str):
    length = len(str)
    str2 = str
    bArr = []
    i = 0
    while i < length:
        # bArr[i/2] = b'\xff\xff\xff'+(str2hex(str2[i]) << 4+str2hex(str2[i+1])).to_bytes(1, "big")
        a = str2[i]
        b = str2[1 + i]
        c = ((str2hex(a) << 4) + str2hex(b))
        bArr.append(c)
        i += 2
    return bArr


def str2hex(s):
    odata = 0;
    su = s.upper()
    for c in su:
        tmp = ord(c)
        if tmp <= ord('9'):
            odata = odata << 4
            odata += tmp - ord('0')
        elif ord('A') <= tmp <= ord('F'):
            odata = odata << 4
            odata += tmp - ord('A') + 10
    return odata


def doGetGzip(url, headers, charset):
    req = request.Request(url)
    for key in headers:
        req.add_header(key, headers[key])
    with request.urlopen(req, ) as f:
        data = f.read()
        return gzip.decompress(data).decode()


def doPostGzip(url, headers, charset, params):
    data = parse.urlencode(params).encode(encoding='UTF8')
    req = request.Request(url)
    for key in headers:
        req.add_header(key, headers[key])
    with request.urlopen(req, data=data) as f:
        data = f.read()
        return gzip.decompress(data).decode()


def testVideo():
    url = "https://api.amemv.com/aweme/v1/aweme/post/?min_cursor=0&max_cursor=0&user_id=3988636999116436&count=12&retry_type=no_retry&iid=109444326057&device_id=71287686249&ac=wifi&channel=wandoujia_aweme1&aid=1128&app_name=aweme&version_code=580&version_name=5.8.0&device_platform=android&ssmix=a&device_type=Redmi+7&device_brand=xiaomi&language=zh&os_api=28&os_version=9&uuid=869770206713501&openudid=fa23302a97ff78d8&manifest_version_code=580&resolution=720*1369&dpi=320&update_version_code=5800&_rticket=1586317529843&mcc_mnc=46000&ts=1586317529&js_sdk_version=1.13.10&as=a145e4573a697ec94c4388&cp=4d96e95ca9ca7095e1QiYm&mas=011e3edaa330cfa2b4aaad7ffd200ad3c91c1ccc2cc62c9cc6a6ec"
    cookies = "odin_tt=040efd2bf4c78c326ebea9cfef43c85c9fd71818c1187c4c4d9b0d1994358d2e26652a7ac37e10bc17dbb6d75b66d8f1581df65cc3b04fa8ec347c776bd32642; d_ticket=7061a2d71f0b7d7f808b8b5b387469b758fe5; sid_guard=5fd28ea88ca3a63af05149dc57643f6a%7C1585289794%7C5184000%7CTue%2C+26-May-2020+06%3A16%3A34+GMT; uid_tt=95140db49dc514a38e2d3f2e397a4801; sid_tt=5fd28ea88ca3a63af05149dc57643f6a; sessionid=5fd28ea88ca3a63af05149dc57643f6a; install_id=109444326057; ttreq=1$33d82222910d9c4ef2f61f17df2610ccf98061b3"
    ts = str(time.time()).split(".")[0]
    _rticket = str(time.time() * 1000).split(".")[0]
    params = url[url.index('?') + 1:]
    STUB = ""
    s = getXGon(params, STUB, cookies)
    gorgon = xGorgon(ts, strToByte(s))
    print(gorgon)
    headers = {
        "X-Gorgon": gorgon,
        "X-SS-REQ-TICKET": "1585711173953",
        "X-Khronos": ts,
        "sdk-version": "1",
        "Accept-Encoding": "gzip",
        "X-SS-REQ-TICKET": _rticket,
        "User-Agent": "com.ss.android.ugc.aweme/580 (Linux; U; Android 9; zh_CN; Redmi 7; Build/PKQ1.181021.001; Cronet/58.0.2991.0)",
        "Host": "api.amemv.com",
        "Cookie": cookies,
        "Connection": "Keep-Alive",
        # "x-tt-token":"00080ab789c0bf0519740314c59de87d8ace96d49d8ab2afd7a0f09cba0911612f99baf92acae289860e0f84ffd97fc2c344"
    }
    result = doGetGzip(url, headers, "UTF-8")
    print(result)


def search_item():
    url = "https://api.amemv.com/aweme/v1/search/item/?manifest_version_code=700&_rticket=1588042256699&app_type=normal&iid=2049122346481144&channel=wandoujia_aweme1&device_type=Redmi%207&language=zh&resolution=720*1369&openudid=23ff9f6b93efea26&update_version_code=7002&os_api=28&dpi=320&ac=wifi&device_id=67765281791&mcc_mnc=46000&os_version=9&version_code=700&app_name=aweme&version_name=7.0.0&js_sdk_version=1.18.1.0&device_brand=xiaomi&ssmix=a&device_platform=android&aid=1128&ts=1588042250"
    params = "keyword=jjj&offset=0&count=10&source=video_search&is_pull_refresh=1&hot_search=0&search_id=&query_correct_type=1"
    params2 = {
        "keyword": "key",
        "offset": 0,
        "count": 10,
        "source": "video_search",
        "is_pull_refresh": 1,
        "hot_search": 0
    }
    cookies = "odin_tt=040efd2bf4c78c326ebea9cfef43c85c9fd71818c1187c4c4d9b0d1994358d2e26652a7ac37e10bc17dbb6d75b66d8f1581df65cc3b04fa8ec347c776bd32642; d_ticket=7061a2d71f0b7d7f808b8b5b387469b758fe5; sid_guard=5fd28ea88ca3a63af05149dc57643f6a%7C1585289794%7C5184000%7CTue%2C+26-May-2020+06%3A16%3A34+GMT; uid_tt=95140db49dc514a38e2d3f2e397a4801; sid_tt=5fd28ea88ca3a63af05149dc57643f6a; sessionid=5fd28ea88ca3a63af05149dc57643f6a; install_id=109444326057; ttreq=1$33d82222910d9c4ef2f61f17df2610ccf98061b3"
    ts = str(time.time()).split(".")[0]
    _rticket = str(time.time() * 1000).split(".")[0]
    STUB = ""
    s = getXGon(params, STUB, cookies)
    gorgon = xGorgon(ts, strToByte(s))
    print(gorgon)
    headers = {
        "X-Gorgon": gorgon,
        "X-SS-REQ-TICKET": "1585711173953",
        "X-Khronos": ts,
        "sdk-version": "1",
        "Accept-Encoding": "gzip",
        "X-SS-REQ-TICKET": _rticket,
        "User-Agent": "com.ss.android.ugc.aweme/700 (Linux; U; Android 9; zh_CN; Redmi 7; Build/PKQ1.181021.001; Cronet/58.0.2991.0)",
        "Host": "aweme.snssdk.com",
        "Cookie": cookies,
        "Connection": "Keep-Alive",
    }
    # result =doGetGzip(url,headers,"UTF-8")
    result = doPostGzip(url, headers, "UTF-8", params2)
    print(result)


def live_test():
    url = "https://webcast3-normal-c-lq.amemv.com/webcast/room/info/?room_id=6824421323302046479&pack_level=3&webcast_sdk_version=1120&os_api=22&device_type=HUAWEI%20MLA-AL10&ssmix=a&manifest_version_code=721&dpi=320&js_sdk_version=1.19.2.0&uuid=863064010168948&app_name=aweme&version_name=7.2.1&ts=1588934410&app_type=normal&ac=wifi&update_version_code=7204&channel=tianzhuo_dy_sg4&_rticket=1588934410268&device_platform=android&iid=4494439458804173&version_code=721&openudid=a85e45a2f9735601&device_id=71048224768&resolution=900*1600&os_version=5.1.1&language=zh&device_brand=HUAWEI&aid=1128&mcc_mnc=46007"
    cookies = "install_id=4494439458804173; ttreq=1$ed7ac0d772116f6326f7d1b2a8636e6029233ee1; d_ticket=76fae73c318bb8721339f3af8799a71c49c70; odin_tt=9c30b37d6e8049a50632bdbd69de05df8d25a3cfce4b9019da8de5336f84d0321dcd6d06e23acc88a0809946a4ec91bba93d46b85f3ad6045bec92b2b6879c58; sid_guard=6cd51f77e2c2daa7cce28b9e6792d279%7C1588836447%7C5184000%7CMon%2C+06-Jul-2020+07%3A27%3A27+GMT; uid_tt=afd1ffc540e9cbd1934bed9566772427; uid_tt_ss=afd1ffc540e9cbd1934bed9566772427; sid_tt=6cd51f77e2c2daa7cce28b9e6792d279; sessionid=6cd51f77e2c2daa7cce28b9e6792d279; sessionid_ss=6cd51f77e2c2daa7cce28b9e6792d279; qh[360]=1"
    params = url[url.index('?') + 1:]
    ts = str(time.time()).split(".")[0]
    _rticket = str(time.time() * 1000).split(".")[0]
    STUB = ""
    s = getXGon(params, STUB, cookies)
    gorgon = xGorgon(ts, strToByte(s))
    headers = {
        "X-Gorgon": gorgon,
        "X-SS-REQ-TICKET": "1585711173953",
        "X-Khronos": ts,
        "sdk-version": "1",
        "Accept-Encoding": "gzip",
        "X-SS-REQ-TICKET": _rticket,
        "User-Agent": "com.ss.android.ugc.aweme/721 (Linux; U; Android 5.1.1; zh_CN; HUAWEI MLA-AL10; Build/HUAWEIMLA-AL10; Cronet/58.0.2991.0)",
        "Host": "webcast3-normal-c-lq.amemv.com",
        "Cookie": cookies,
        "Connection": "Keep-Alive",
        "x-tt-token": "006cd51f77e2c2daa7cce28b9e6792d279ac380936bb11c43b53547e236d78cb08e7b964068edb33123054e653c7770d0f12"
    }
    result = doGetGzip(url, headers, "UTF-8")
    print(result)


if __name__ == "__main__":
    # testVideo()
    # search_item()
    # live_test()
    url = "https://aweme.snssdk.com/aweme/v2/comment/list/?aweme_id=6810650141905669383&cursor=0&count=20&address_book_access=1&gps_access=1&forward_page_type=1&os_api=22&device_type=MI%205s&ssmix=a&manifest_version_code=920&dpi=192&uuid=869273222474044&app_name=aweme&version_name=9.2.0&ts=1585739874&app_type=normal&ac=wifi&update_version_code=9202&channel=aweGW&_rticket=1585739874633&device_platform=android&iid=110128576639&version_code=920&cdid=e7d2d302-0ff6-4774-8750-acec805feb67&openudid=f4c3dc16590ada36&device_id=69567395847&resolution=1280*720&os_version=5.1.1&language=zh&device_brand=Xiaomi&aid=1128&mcc_mnc=46000"
    ts = str(time.time()).split(".")[0]
    _rticket = str(time.time() * 1000).split(".")[0]
    cookies = "install_id=110128576639; ttreq=1$b3de35bd51c867f4a291a7f697bf4f5d3da252f4; passport_csrf_token=eae0cb8afd7ae83568ac9eb0d470b35d; d_ticket=f6d6d5c5aa2a95349b6fb01c0f8f029e1cf3b; odin_tt=ca86a870c665e2857ec3af1df759ee747bcadae223cd706f61e55ce4352bc4ed8d6af5bb42a78ecaa7714daccc9884639f2b2f36d4231ce5bab18051f91d9b11; sid_guard=080ab789c0bf0519740314c59de87d8a%7C1585711138%7C5184000%7CSun%2C+31-May-2020+03%3A18%3A58+GMT; uid_tt=f02935cf52727202351fb06c888f4a28; sid_tt=080ab789c0bf0519740314c59de87d8a; sessionid=080ab789c0bf0519740314c59de87d8a"
    params = url[url.index('?') + 1:]
    STUB = ""
    s = getXGon(params, STUB, cookies)
    gorgon = xGorgon(ts, strToByte(s))
    headers = {
        "X-Gorgon": gorgon,
        "X-SS-REQ-TICKET": "1585711173953",
        "X-Khronos": ts,
        "sdk-version": "1",
        "Accept-Encoding": "gzip",
        "X-SS-REQ-TICKET": _rticket,
        "User-Agent": "ttnet okhttp/3.10.0.2",
        "Host": "aweme.snssdk.com",
        "Cookie": cookies,
        "Connection": "Keep-Alive",
        "x-tt-token": "00080ab789c0bf0519740314c59de87d8ace96d49d8ab2afd7a0f09cba0911612f99baf92acae289860e0f84ffd97fc2c344"
    }
    result = doGetGzip(url, headers, "UTF-8")
    print(result)
