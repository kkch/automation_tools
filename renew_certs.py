#! /usr/bin/env python
import requests
import salt.client
import json

master = salt.client.LocalClient()
res = master.cmd('cfg*', 'pillar.items', ['linux:network:host:mon:address'])
for a in res:
    ip = res[a]['linux:network:host:mon:address']

url = "http://{ip}:15011/api/v1/alerts".format(ip=ip)

r = requests.get(url)
data = r.json()['data']


def simplify(alert):
    if alert['labels']['alertname'] in {'CertificateExpirationWarning',
                                        'CertificateExpirationCritical'}:
        return {
            'host': alert['labels']['host'],
            'file': alert['labels']['source']
        }

alerts = list(filter(None, map(simplify, data)))

for alert in alerts:
    host = alert['host']
    cert = alert['file']
    cert_issuer = master.cmd(host+'*', 'cmd.run',
                             ['openssl x509 -issuer -noout -in ' + cert])
    cert_date = master.cmd(host+'*', 'cmd.run',
                           ['openssl x509 -enddate -noout -in ' + cert])
    cert_expiry = cert_date.values()[0].split('=')[1]
    issuer = cert_issuer.values()[0].split(" ", 1)[1]
    if any("CN=Salt Master CA" in word for word in cert_issuer.values()):
        print("cert: {cert} on {host} is expiring on {cert_expiry} "
              "signed by {issuer} and can be renewed"
              .format(cert=cert, host=host, issuer=issuer,
                      cert_expiry=cert_expiry))
