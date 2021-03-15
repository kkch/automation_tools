#! /usr/bin/env python
import requests
import salt.client
import salt
import json
import logging
import sys
import argparse
from datetime import datetime

timestamp = datetime.now().strftime("%d%b%Y%H%M")

services = ['td-agent',
            'telegraf',
            'libvirt',
            'rabbitmq',
            'mysql',
            'nova-novncproxy',
            'salt-api']

servers = {}

logfile = '/tmp/renew_cert.log.{timestamp}'.format(timestamp=timestamp)
logging.basicConfig(filename=logfile, level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s: %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p')

master = salt.client.LocalClient()

errors_countered = False


def parse_argument():
    """Parse commandline arguments"""
    parser = argparse.ArgumentParser(prog='Renew Certs')
    parser.add_argument('--test', '-t', action='store_true',
                        help='Run script in dryrun mode')
    parser.add_argument('--version', '-v', action='version',
                        version='%(prog)s 1.0')
    args = parser.parse_args()
    return args


def generate_url():
    """Generate url from Salt pillar data"""
    try:
        res = master.cmd('cfg*', 'pillar.items',
                         ['linux:network:host:mon:address'])
    except salt.exceptions.EauthAuthenticationError as e:
        logging.error(e)
        sys.exit('Run as root or sudo')
    for a in res:
        ip = res[a]['linux:network:host:mon:address']
    url = "http://{ip}:15011/api/v1/alerts".format(ip=ip)
    return url


def gather_alerts(url):
    """Gather all firing alerts"""
    try:
        r = requests.get(url)
    except requests.ConnectionError as e:
        logging.error(e)
        sys.exit("An ERROR occured while connecting to api endpoint."
                 " Check logs for details")
    else:
        if r.status_code == 200:
            data = r.json()['data']
            return data
        else:
            logging.error('Could not get the data,status code {status_code}'
                          .format(status_code=r.status_code))
            sys.exit("Error!! Cloud not get the data, Check the logs!")


def simplify(alert):
    """Filter cert alerts"""
    if alert['labels']['alertname'] in {'CertificateExpirationWarning',
                                        'CertificateExpirationCritical'}:
        return {
            'host': alert['labels']['host'],
            'file': alert['labels']['source']
        }


def add_values_in_dict(sample_dict, key, list_of_values):
    """Append multiple values to a key in the given dictionary"""
    if key not in sample_dict:
        sample_dict[key] = list()
    sample_dict[key].extend(list_of_values)
    temp_list = sample_dict[key]
    temp_list = list(set(temp_list))  # remove duplicates
    sample_dict[key] = temp_list
    return sample_dict


def backup_certs(args):
    """Back up certs only in non-dryrun mode"""
    for alert in alerts:
        host = alert['host']
        cert = alert['file']
        cert_issuer = master.cmd('*' + host + '*', 'cmd.run',
                                 ['openssl x509 -issuer -noout -in ' + cert])
        if any("CN=Salt Master CA" in word for word in cert_issuer.values()):
            if not args.test:
                logging.info("[{host}] - backing up {cert}"
                             .format(cert=cert, host=host))
                result = master.cmd('*' + host + '*', 'file.rename',
                                    [cert, cert+timestamp])
                if any("ERROR" in word for word in result.values()):
                    logging.error("[{host}] - could not back up {cert}"
                                  .format(cert=cert, host=host))
                    errors_countered = True
                    continue
            service = [ele for ele in services if(ele in cert)]
            servers = add_values_in_dict(servers, host, service)


def renew_certs(args):
    """renew certs and restart services"""
    for key in servers:
        host = key
        services = servers[key]
        if args.test:
            master.cmd('*' + host + '*', 'state.sls', ['salt.minion.grains',
                                                       'test=true'])
            logging.info("Dryrun: [{host}] - salt.minion.grains state"
                         .format(host=host))
            master.cmd('*' + host + '*', 'state.sls', ['salt.minion.cert',
                                                       'test=true'])
            logging.info("Dryrun: [{host}] - salt.minion.cert state"
                         .format(host=host))
        else:
            master.cmd('*' + host + '*', 'state.sls', ['salt.minion.grains'])
            master.cmd('*' + host + '*', 'state.sls', ['salt.minion.cert'])
            for service in services:
                logging.info("[{host}] - restarting {service}"
                             .format(host=host, service=service))
                if service == "td-agent":
                    result = master.cmd(
                        '*' + host + '*', 'service.restart', [service])
                    if any("ERROR" in word for word in result.values()):
                        errors_countered = True
                        logging.error("[{host}] - could not restart service: "
                                      "{service}".format(
                                          host=host, service=service))
                if service == "telegraf":
                    result = master.cmd(
                        '*' + host + '*', 'service.restart', [service])
                    if any("ERROR" in word for word in result.values()):
                        errors_countered = True
                        logging.error("[{host}] - could not restart service: "
                                      "{service}".format(
                                          host=host, service=service))
                if service == "mysql":
                    result = master.cmd(
                        '*' + host + '*', 'service.restart', [service])
                    if any("ERROR" in word for word in result.values()):
                        errors_countered = True
                        logging.error("[{host}] - could not restart service: "
                                      "{service}".format(
                                          host=host, service=service))
                if service == "libvirt":
                    service = 'libvirtd'
                    if "cmp" in host:
                        result = master.cmd('*' + host + '*',
                                            'service.restart', [service])
                        if any("ERROR" in word for word in result.values()):
                            errors_countered = True
                            logging.error("[{host}] - could not restart service:"
                                          "{service}".format(
                                              host=host, service=service))
                if service == "rabbitmq":
                    service = 'rabbitmq-server'
                    if "msg" in host:
                        result = master.cmd('*' + host + '*', 'service.restart',
                                            [service])
                        if any("ERROR" in word for word in result.values()):
                            errors_countered = True
                            logging.error("[{host}] - could not restart service: "
                                          "{service}".format(
                                              host=host, service=service))
                if service == "nova-novncproxy":
                    if "ctl" in host:
                        result = master.cmd('*' + host + '*', 'service.restart',
                                            [service])
                        if any("ERROR" in word for word in result.values()):
                            errors_countered = True
                            logging.error("[{host}] - could not restart service: "
                                          "{service}".format(
                                              host=host, service=service))
                if service == "salt-api":
                    if "cfg" in host:
                        result = master.cmd('*' + host + '*', 'service.restart',
                                            [service])
                        if any("ERROR" in word for word in result.values()):
                            errors_countered = True
                            logging.error("[{host}] - could not restart service: "
                                          "{service}".format(
                                              host=host, service=service))


def main():
    print("Staring script ....")
    print("Parsing arguments ....")
    args = parse_argument()
    print("Generating url ....")
    url = generate_url()
    print("Gathering alerts ....")
    data = gather_alerts(url)
    print("Filtering current alerts")
    alerts = list(filter(None, map(simplify, data)))
    print(alerts)
    print("backing up certs ....")
    backup_certs(args)
    print(servers)
    print("Renewing certs ....")
    renew_certs(args)
    if errors_countered:
        sys.exit("Error !! Check logs for details")
    else:
        sys.exit()


if __name__ == "__main__":
    main()
