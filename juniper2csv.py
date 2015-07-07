#!/usr/bin/python3

from lxml import etree
from io import StringIO
import argparse


parser = argparse.ArgumentParser()

parser.add_argument("-f", "--file", dest="filename", required=True, metavar="FILE", help="XML File to convert")

args = parser.parse_args()

file = open(args.filename, 'r')

xml = file.read()

file.close()

tree = etree.parse(StringIO(xml))


def get_address_set(zone, address_set):
    """
    :param zone: Name of the zone where the address_set is related to
    :param address_set: address_set to find
    :return: return members of the address_set
    """
    result = []
    for address_ in address_set:
        addresses = tree.xpath(
            "/rpc-reply/configuration/security/zones/security-zone[name = '" + zone
            + "']/address-book/address-set[name = '" + address_ + "']/address/name/text()")
        if len(addresses) == 0:
            addresses = get_ip(zone, [address_])

        result = result + addresses
    return result


def get_ip(zone, address_):
    """
    :param zone: Name of the zone where the address_set is related to
    :param address_: Name of the object address to find
    :return: Return the IP address of the object
    """
    result = []
    for ip in address_:
        address = tree.xpath(
            "/rpc-reply/configuration/security/zones/security-zone[name = '" + zone
            + "']/address-book/address[name = '" + ip + "']/ip-prefix/text()")
        if len(address) == 0:
            result = result + [ip]
        else:
            result = result + address
    return result


policies_racine = "/rpc-reply/configuration/security/policies/policy"
""" XML root for policies """

policies_root = tree.xpath(policies_racine)
""" Parse policies_root tree """

policies_root_occurences = (len(policies_root))
policy_root_counter = 1

s_policy_sum = 0

print(
    "'name';'from-zone-name';'to-zone-name';'source-address';'destination-address';"
    "'application';'action';'inactive';'log'")

while policy_root_counter <= policies_root_occurences:
    policies_from = tree.xpath(
        policies_racine+"[" + str(policy_root_counter) + "]/from-zone-name")
    policies_to = tree.xpath(policies_racine+"[" + str(policy_root_counter) + "]/to-zone-name")
    policy_number = tree.xpath(policies_racine+"[" + str(policy_root_counter) + "]/policy")
    spn = len(policy_number)
    s_policy = 1
    while s_policy <= spn:

        policy_inactive = tree.xpath(
            policies_racine+"[" + str(policy_root_counter) + "]/policy[" + str(
                s_policy) + "]/@inactive")

        policy_name = tree.xpath(
            policies_racine+"[" + str(policy_root_counter) + "]/policy[" + str(
                s_policy) + "]/name")
        source_addresses = tree.xpath(
            policies_racine+"[" + str(policy_root_counter) + "]/policy[" + str(
                s_policy) + "]/match/source-address")
        destination_addresses = tree.xpath(
            policies_racine+"[" + str(policy_root_counter) + "]/policy[" + str(
                s_policy) + "]/match/destination-address")
        applications = tree.xpath(
            policies_racine+"[" + str(policy_root_counter) + "]/policy[" + str(
                s_policy) + "]/match/application")

        actions = tree.xpath(
            policies_racine+"[" + str(policy_root_counter) + "]/policy[" + str(
                s_policy) + "]/then/permit")
        if len(actions) == 0:
            actions = tree.xpath(
                policies_racine+"[" + str(policy_root_counter) + "]/policy[" + str(
                    s_policy) + "]/then/deny")

        logs = tree.xpath(policies_racine+"[" + str(policy_root_counter) + "]/policy[" + str(
            s_policy) + "]/then/log/*")

        csvline = {}

        for policy_from in policies_from:
            csvline["from-zone-name"] = policy_from.text

        for policy_to in policies_to:
            csvline["to-zone-name"] = policy_to.text

        csvline["inactive"] = policy_inactive

        csvline["name"] = policy_name[0].text

        src = []
        for source_address in source_addresses:
            src.append(source_address.text)

        csvline['source-address'] = src
        csvline['source-address'] = get_ip(csvline['from-zone-name'],
                                           get_address_set(csvline['from-zone-name'], csvline['source-address']))

        dst = []
        for destination_address in destination_addresses:
            dst.append(destination_address.text)

        csvline['destination-address'] = dst
        csvline['destination-address'] = get_ip(csvline['to-zone-name'], get_address_set(csvline['to-zone-name'],
                                                                                         csvline[
                                                                                             'destination-address']))

        app = []
        for application in applications:
            app.append(application.text)

        csvline['application'] = app

        act = []
        for action in actions:
            act.append(action.tag)

        csvline['action'] = act

        l = []
        for log in logs:
            l.append(log.tag)

        csvline["log"] = l

        s_policy += 1

        for d in csvline['destination-address']:
            for s in csvline['source-address']:
                for p in csvline['application']:
                    print("'{}';'{}';'{}';'{}';'{}';'{}';'{}';'{}';'{}'".format(csvline['name'],
                                                                                csvline['from-zone-name'],
                                                                                csvline['to-zone-name'], s,
                                                                                d, p, csvline['action'],
                                                                                csvline['inactive'], csvline['log']))
    policy_root_counter += 1
    s_policy_sum = s_policy_sum + s_policy

print("{} root policies et {} sub policies".format(policy_root_counter,s_policy_sum))
