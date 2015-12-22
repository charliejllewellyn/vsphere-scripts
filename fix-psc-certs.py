#!/usr/bin/python

import htmllib
import re
import formatter
import string
import subprocess
import HTMLParser
from cStringIO import StringIO
import sys
import argparse
import getpass

parser = argparse.ArgumentParser(description="Cert fix params")
parser.add_argument('-user', dest='username', type=str, required=True)
parser.add_argument('-pscFQDN', dest='pscHostname', type=str, required=True)
parser.add_argument('-ssoDomain', dest='ssoDomain', type=str, required=True)

username = parser.parse_args().username
pscHostname = parser.parse_args().pscHostname
ssoDomain = parser.parse_args().ssoDomain

password = getpass.getpass(prompt="Enter SSO administrator password")

class TableParser(HTMLParser.HTMLParser):
    def __init__(self):
        HTMLParser.HTMLParser.__init__(self)
        self.in_td = False

    def handle_starttag(self, tag, attrs):
        if tag == 'td':
            self.in_td = True

    def handle_data(self, data):
        if self.in_td:
            print data

    def handle_endtag(self, tag):
        self.in_td = False

def runLocalCmd(cmd):

    p1 = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    output = p1.communicate()[0]
    return output

login = runLocalCmd("curl -k -u " + username + ":'" + password + "' 'https://" + pscHostname + "/lookupservice/mob?moid=ServiceRegistration&method=List' -i")
p = re.compile("Set-Cookie: vmware_debug_session=(.*); Path=/lookupservice")
r = re.compile('.*vmware-session-nonce" type="hidden" value="(.*)"><p class="t.*')
for line in string.split(login, '\n'):
        m = p.match(line)
        m2 = r.match(line)
        if m:
                cookie = m.group(1)
        if m2:
                nonce = m2.group(1)

data = runLocalCmd('curl -k -s -u ' + username + ":'" + password + "'" + ' "https://' + pscHostname + '/lookupservice/mob?moid=ServiceRegistration&method=List" -H "Cookie: vmware_debug_session=' + cookie + '" -H "Origin: https://' + pscHostname + '" -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: en-US,en;q=0.8" -H "Content-Type: application/x-www-form-urlencoded" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" -H "Cache-Control: max-age=0" -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.115 Safari/537.36" -H "Connection: keep-alive" -H "Referer: https://' + pscHostname + '/lookupservice/mob?moid=ServiceRegistration&method=List" --data "vmware-session-nonce=' + nonce + '&filterCriteria="%"3CfilterCriteria"%"3E"%"3C"%"2FfilterCriteria"%"3E" --compressed')

old_stdout = sys.stdout
sys.stdout = mystdout = StringIO()

p = TableParser()
p.feed(data)
sys.stdout = old_stdout
moRefs = []
for line in string.split(mystdout.getvalue(), '\n'):
    moRefs.append(line)

indexNum = moRefs.index("https://" + pscHostname + "/sts/STSService/" + ssoDomain) - 3
#for i, v in enumerate(moRefs):
#    print i, v
certTemp = []
certTemp2 = []
old_cert = moRefs[indexNum]
if old_cert == "":
    for num in range(19):
        num + 4
        certTemp.append(re.sub("\r", "", moRefs[indexNum - num]))
    for i in reversed(certTemp):
        certTemp2.append(i)
        old_cert = "".join(certTemp2)
old_cert = "-----BEGIN CERTIFICATE-----\n" + re.sub("(.{64})", "\\1\n", old_cert, 0) + "\n-----END CERTIFICATE-----"

runLocalCmd("mkdir /certificate")
f = open('/certificate/old_machine.crt', 'w')
f.write(old_cert)
f.close()
runLocalCmd("/usr/lib/vmware-vmafd/bin/vecs-cli entry getcert --store MACHINE_SSL_CERT --alias __MACHINE_CERT --output /certificate/new_machine.crt")
old_thumbprint = re.sub("SHA1 Fingerprint=", "", runLocalCmd("openssl x509 -in /certificate/old_machine.crt -noout -sha1 -fingerprint"))
old_thumbprint = re.sub("\n", "", old_thumbprint)
print "replacing certs. This can take a couple of minutes..."
print runLocalCmd("cd /usr/lib/vmidentity/tools/scripts/ && python ls_update_certs.py --url https://" + pscHostname + "/lookupservice/sdk --fingerprint " + old_thumbprint + " --certfile /certificate/new_machine.crt --user " + username + " --password '" + password + "'")
