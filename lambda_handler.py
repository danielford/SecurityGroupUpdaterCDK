import boto3
import itertools
import socket
import copy
import pprint


TAG_ENABLED = "SecurityGroupUpdater_Enabled"
ENABLED_VALUES = ['t', "true", "1", "yes", 'y']

TAG_INGRESS_DNS_NAME = "SecurityGroupUpdater_IngressDNSName"
TAG_INGRESS_PORTS = "SecurityGroupUpdater_IngressPorts"

def port_to_ingress_rule(cidr_ip, port_value):
    port_value = port_value.lower()

    if port_value == 'ssh':
        proto = 'tcp'
        from_port = to_port = 22
    elif port_value.startswith('tcp') and port_value[3:].isalnum():
        proto = 'tcp'
        from_port = to_port = int(port_value[3:])
    elif port_value.startswith('udp') and port_value[3:].isalnum():
        proto = 'udp'
        from_port = to_port = int(port_value[3:])
    elif port_value == 'icmp':
        proto = 'icmp'
        from_port = to_port = -1
    else:
        raise ValueError("Bad port/protocol specification: %s" % port_value)

    return {
        'FromPort': from_port,
        'ToPort': to_port,
        'IpProtocol': proto,
        'IpRanges': [ { 'CidrIp': cidr_ip } ]
    }

def desired_ingress_rules(cidr_ip, ingress_ports_value):
    return [port_to_ingress_rule(cidr_ip, x) for x in ingress_ports_value.split(',')]


def update_ingress_rules(ec2_client, group_id, desired_rules, actual_rules):
    desired_rules = copy.deepcopy(desired_rules)
    actual_rules = copy.deepcopy(actual_rules)

    cmp_keys = ['FromPort', 'ToPort', 'IpProtocol', 'IpRanges']
    rules_to_delete = []

    for rule in actual_rules:
        cmp = {k: rule[k] for k in cmp_keys}

        if cmp in desired_rules:
            desired_rules.remove(cmp)
        else:
            rules_to_delete.append(cmp)

    if desired_rules:
        ec2_client.authorize_security_group_ingress(
            GroupId=group_id,
            IpPermissions=desired_rules)

    if rules_to_delete:
        ec2_client.revoke_security_group_ingress(
            GroupId=group_id,
            IpPermissions=rules_to_delete)

def find_security_groups(ec2_client):
    enabled_value_variants = [[x, x.upper(), x.lower().capitalize()] for x in ENABLED_VALUES]
    all_enabled_values = list(set(itertools.chain.from_iterable(enabled_value_variants)))

    response = ec2_client.describe_security_groups(
        Filters=[{'Name': "tag:%s" % TAG_ENABLED, 'Values': all_enabled_values}])
    
    return response['SecurityGroups']

def resolve_dns_name_to_cidr(dns_name):
    return "%s/32" % socket.gethostbyname(dns_name)


def main(event, context):
    print('SecurityGroupUpdater running')

    pp = pprint.PrettyPrinter(indent=2)
    ec2 = boto3.client('ec2')

    security_groups = find_security_groups(ec2)
    failed_groups = []

    for group in security_groups:
        group_name = group['GroupName']
        group_id = group['GroupId']
        tags = group['Tags']

        print("Found group '%s' with id: %s" % (group_name, group_id))
        pp.pprint(group)

        try:
            dns_name = ports_spec = None

            for tag in tags:
                if tag['Key'] == TAG_INGRESS_DNS_NAME:
                    dns_name = tag['Value']
                if tag['Key'] == TAG_INGRESS_PORTS:
                    ports_spec = tag['Value']
            
            if dns_name is None:
                raise RuntimeError('Missing tag: %s' % TAG_INGRESS_DNS_NAME)

            if ports_spec is None:
                raise RuntimeError('Missing tag: %s' % TAG_INGRESS_PORTS)
            
            cidr_ip = resolve_dns_name_to_cidr(dns_name)
            desired_rules = desired_ingress_rules(cidr_ip, ports_spec)
            actual_rules = group['IpPermissions']

            update_ingress_rules(ec2, group_id, desired_rules, actual_rules)

        except Exception as e:
            print(e)
            print('Error updating ingress rules for group %s: %s' % (group_id, e))
            failed_groups.append(group_id)

    if failed_groups:
        raise RuntimeError('%d security groups failed to update: %s' % (len(failed_groups), ', '.join(failed_groups)))

    print('SecurityGroupUpdater finished running successfully')
