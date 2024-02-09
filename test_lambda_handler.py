import pytest
from unittest import mock

from lambda_handler import desired_ingress_rules, resolve_dns_name_to_cidr, update_ingress_rules


def test_update_ingress_rules_no_change():
    ec2_client = mock.Mock()

    desired_rules = [{
        'FromPort': 22,
        'ToPort': 22,
        'IpProtocol': 'tcp',
        'IpRanges': [ {'CidrIp': '1.2.3.4/32'}]
    }]
    actual_rules = [{
        'FromPort': 22,
        'ToPort': 22,
        'IpProtocol': 'tcp',
        'IpRanges': [ {'CidrIp': '1.2.3.4/32'}],
    }]
    update_ingress_rules(ec2_client, 'g-123', desired_rules, actual_rules)
    ec2_client.assert_not_called()

def test_update_ingress_rules_port_changed():
    ec2_client = mock.Mock()

    desired_rules = [{
        'FromPort': 22,
        'ToPort': 22,
        'IpProtocol': 'tcp',
        'IpRanges': [ {'CidrIp': '1.2.3.4/32'}]
    }]
    actual_rules = [{
        'FromPort': 33,
        'ToPort': 33,
        'IpProtocol': 'tcp',
        'IpRanges': [ {'CidrIp': '1.2.3.4/32'}],
    }]
    update_ingress_rules(ec2_client, 'g-123', desired_rules, actual_rules)
    ec2_client.revoke_security_group_ingress.assert_called_with(GroupId='g-123', IpPermissions=actual_rules)
    ec2_client.authorize_security_group_ingress.assert_called_with(GroupId='g-123', IpPermissions=desired_rules)

def test_update_ingress_rules_cidr_changed():
    ec2_client = mock.Mock()

    desired_rules = [{
        'FromPort': 22,
        'ToPort': 22,
        'IpProtocol': 'tcp',
        'IpRanges': [ {'CidrIp': '4.5.6.7/32'}]
    }]
    actual_rules = [{
        'FromPort': 22,
        'ToPort': 22,
        'IpProtocol': 'tcp',
        'IpRanges': [ {'CidrIp': '1.2.3.4/32'}],
    }]
    update_ingress_rules(ec2_client, 'g-123', desired_rules, actual_rules)
    ec2_client.revoke_security_group_ingress.assert_called_with(GroupId='g-123', IpPermissions=actual_rules)
    ec2_client.authorize_security_group_ingress.assert_called_with(GroupId='g-123', IpPermissions=desired_rules)

def test_update_ingress_rules_multiple_removal():
    ec2_client = mock.Mock()

    desired_rules = [{
        'FromPort': 22,
        'ToPort': 22,
        'IpProtocol': 'tcp',
        'IpRanges': [ {'CidrIp': '1.2.3.4/32'}]
    }]
    actual_rules = [
    {
        'FromPort': 22,
        'ToPort': 22,
        'IpProtocol': 'tcp',
        'IpRanges': [ {'CidrIp': '1.2.3.4/32'}]
    },
    {
        'FromPort': 22,
        'ToPort': 22,
        'IpProtocol': 'tcp',
        'IpRanges': [ {'CidrIp': '3.4.5.6/32'}],
    },
    {
        'FromPort': 22,
        'ToPort': 22,
        'IpProtocol': 'tcp',
        'IpRanges': [ {'CidrIp': '2.3.4.5/32'}],
    }]

    update_ingress_rules(ec2_client, 'g-123', desired_rules, actual_rules)
    ec2_client.revoke_security_group_ingress.assert_called_with(GroupId='g-123', IpPermissions=actual_rules[1:3])
    ec2_client.authorize_security_group_ingress.assert_not_called()

def test_resolve_dns_name_to_cidr():
    with mock.patch("socket.gethostbyname", return_value="1.2.3.4"):
        assert resolve_dns_name_to_cidr('home-ip.danford.dev') == '1.2.3.4/32'

def test_desired_ingress_rules_multiple():
    rules = desired_ingress_rules('1.2.3.4/32', 'ssh,udp123,tcp456,icmp')

    assert rules == [
    {
        'FromPort': 22,
        'ToPort': 22,
        'IpProtocol': 'tcp',
        'IpRanges': [{ 'CidrIp': '1.2.3.4/32' }]
    },
    {
        'FromPort': 123,
        'ToPort': 123,
        'IpProtocol': 'udp',
        'IpRanges': [{ 'CidrIp': '1.2.3.4/32' }]
    },
    {
        'FromPort': 456,
        'ToPort': 456,
        'IpProtocol': 'tcp',
        'IpRanges': [{ 'CidrIp': '1.2.3.4/32' }]
    },
    {
        'FromPort': -1,
        'ToPort': -1,
        'IpProtocol': 'icmp',
        'IpRanges': [{ 'CidrIp': '1.2.3.4/32' }]
    }]

def test_desired_ingress_rules_icmp():
    rules = desired_ingress_rules('1.2.3.4/32', 'icmp')
    assert rules == [{
        'FromPort': -1,
        'ToPort': -1,
        'IpProtocol': 'icmp',
        'IpRanges': [ { 'CidrIp': '1.2.3.4/32' }]
    }]

def test_desired_ingress_rules_udp():
    rules = desired_ingress_rules('1.2.3.4/32', 'udp19132')
    assert rules == [{
        'FromPort': 19132,
        'ToPort': 19132,
        'IpProtocol': 'udp',
        'IpRanges': [ { 'CidrIp': '1.2.3.4/32' }]
    }]

def test_desired_ingress_rules_tcp():
    rules = desired_ingress_rules('1.2.3.4/32', 'tcp80')
    assert rules == [{
        'FromPort': 80,
        'ToPort': 80,
        'IpProtocol': 'tcp',
        'IpRanges': [ { 'CidrIp': '1.2.3.4/32' }]
    }]

def test_desired_ingress_rules_ssh():
    rules = desired_ingress_rules('1.2.3.4/32', 'ssh')
    assert rules == [{
        'FromPort': 22,
        'ToPort': 22,
        'IpProtocol': 'tcp',
        'IpRanges': [ { 'CidrIp': '1.2.3.4/32' }]
    }]

