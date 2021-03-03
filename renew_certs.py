#! /usr/bin/env python
# request module to query api
import requests
# salt api to make salt calls
import salt.client

# configuring salt client
master = salt.client.LocalClient()
# salt call to get ip of mon 
res = master.cmd('cfg*','pillar.items', ['linux:network:host:mon:address'])
for a in res:
    ip = res[a]['linux:network:host:mon:address']

url = "http://{ip}:15011/api/v1/alerts".format(ip=ip)

r = requests.get(url)
data = r.json()
query = data['data']

# looping through retuned json data from api query
for i in range(len(query)):
    if query[i]['labels']['alertname'] in {'CertificateExpirationWarning','CertificateExpirationCritical'}:
        host = query[i]['labels']['host']
        cert = query[i]['labels']['source']
        cert_issuer = master.cmd(host+'*', 'cmd.run', ['openssl x509 -issuer -noout -in '+cert])
        cert_date = master.cmd(host+'*', 'cmd.run', ['openssl x509 -dates -noout -in '+cert])
        cert_expiry = cert_date.values()[0].split("\n")[1].split('=')[1]
        issuer = cert_issuer.values()[0].split("/")[2]
        if issuer == 'CN=Salt Master CA':
            print('cert: {cert} on {host} is expiring on {cert_expiry}signed by {issuer} and can be renewed.'.format(cert=cert,host=host,issuer=issuer,cert_expiry=cert_expiry))
        else:
            pass
