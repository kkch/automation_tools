#! /usr/bin/env python
import requests
import salt.client
import json
from datetime import date

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

services = ['td-agent',
            'telegraf',
            'libvirt',
            'rabbitmq',
            'mysql',
            'nova-novncproxy',
            'salt-api']

timestamp = date.today().strftime("%d%b%Y")

servers = {}


def add_values_in_dict(sample_dict, key, list_of_values):
    """Append multiple values to a key in the given dictionary"""
    if key not in sample_dict:
        sample_dict[key] = list()
    sample_dict[key].extend(list_of_values)
    temp_list = sample_dict[key]
    temp_list = list(set(temp_list))  # remove duplicates
    sample_dict[key] = temp_list
    return sample_dict

for alert in alerts:
    host = alert['host']
    cert = alert['file']
    cert_issuer = master.cmd('*' + host + '*', 'cmd.run',
                             ['openssl x509 -issuer -noout -in ' + cert])
    if any("CN=Salt Master CA" in word for word in cert_issuer.values()):
        result = master.cmd('*' + host + '*', 'file.rename',
                            [cert, cert+timestamp])
        if any("ERROR" in word for word in result.values()):
            print("[{host}] ERROR - could not back up {cert}"
                  .format(cert=cert, host=host))
            continue
        service = [ele for ele in services if(ele in cert)]
        servers = add_values_in_dict(servers, host, service)

for key in servers:
    host = key
    services = servers[key]
    master.cmd('*' + host + '*', 'state.sls', ['salt.minion.grains'])
    master.cmd('*' + host + '*', 'state.sls', ['salt.minion.cert'])
    for service in services:
        if service == "td-agent":
            result = master.cmd('*' + host + '*', 'service.restart', [service])
            if any("ERROR" in word for word in result.values()):
                print("[{host}] ERROR - could not restart service: "
                      "{service}".format(host=host, service=service))
        if service == "telegraf":
            result = master.cmd('*' + host + '*', 'service.restart', [service])
            if any("ERROR" in word for word in result.values()):
                print("[{host}] ERROR - could not restart service: "
                      "{service}".format(host=host, service=service))
        if service == "mysql":
            result = master.cmd('*' + host + '*', 'service.restart', [service])
            if any("ERROR" in word for word in result.values()):
                print("[{host}] ERROR - could not restart service: "
                      "{service}".format(host=host, service=service))
        if service == "libvirt":
            service = 'libvirtd'
            if "cmp" in host:
                result = master.cmd('*' + host + '*', 'service.restart',
                                    [service])
                if any("ERROR" in word for word in result.values()):
                    print("[{host}] ERROR - could not restart service: "
                          "{service}".format(host=host, service=service))
        if service == "rabbitmq":
            service = 'rabbitmq-server'
            if "msg" in host:
                result = master.cmd('*' + host + '*', 'service.restart',
                                    [service])
                if any("ERROR" in word for word in result.values()):
                    print("[{host}] ERROR - could not restart service: "
                          "{service}".format(host=host, service=service))
        if service == "nova-novncproxy":
            if "ctl" in host:
                result = master.cmd('*' + host + '*', 'service.restart',
                                    [service])
                if any("ERROR" in word for word in result.values()):
                    print("[{host}] ERROR - could not restart service: "
                          "{service}".format(host=host, service=service))
        if service == "salt-api":
            if "cfg" in host:
                result = master.cmd('*' + host + '*', 'service.restart',
                                    [service])
                if any("ERROR" in word for word in result.values()):
                    print("[{host}] ERROR - could not restart service: "
                          "{service}".format(host=host, service=service))
