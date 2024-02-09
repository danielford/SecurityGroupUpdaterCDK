#!/usr/bin/env python3

import sys
import urllib.request
import boto3


def update_route53_dynamic_dns(hosted_zone_id, dyn_dns_name):
    print("Route 53 dynamic DNS updater running...")

    external_ip = urllib.request.urlopen('https://checkip.amazonaws.com').read().decode('utf8').rstrip()

    client = boto3.client('route53')

    response = client.list_resource_record_sets(HostedZoneId=hosted_zone_id, StartRecordName=dyn_dns_name, MaxItems='1')
    record_sets = response['ResourceRecordSets']

    if record_sets:
        if 'ResourceRecords' in record_sets[0]:
            if record_sets[0]['ResourceRecords']:
                if record_sets[0]['ResourceRecords'][0]['Value'] == external_ip:
                    print('Dynamic IP is already correct, nothing to do')
                    return

    print('Updating %s to %s' % (dyn_dns_name, external_ip))

    client.change_resource_record_sets(
        HostedZoneId=hosted_zone_id,
        ChangeBatch={
            'Comment': 'Automated change by route53_updater.py',
            'Changes': [{
                'Action': 'UPSERT',
                'ResourceRecordSet': {
                    'Name': dyn_dns_name,
                    'Type': 'A',
                    'TTL': 300,
                    'ResourceRecords': [{ 'Value': external_ip }]
                }
            }]
        }
    )

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print('Usage: %s [HOSTED_ZONE_ID] [DYN_DNS_NAME]')
        exit(1)

    update_route53_dynamic_dns(sys.argv[1], sys.argv[2])
