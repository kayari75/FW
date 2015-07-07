#!/usr/bin/python

from lxml import etree
from io import StringIO
import argparse
import re

parser = argparse.ArgumentParser()

parser.add_argument("-f", "--file", dest="filename", required=True, metavar="FILE", help="XML File to convert")

args = parser.parse_args()

file = open(args.filename, 'r')

xml = file.read()

file.close()

tree = etree.parse(StringIO(xml))


def ipRange(start_ip, end_ip):
   start = list(map(int, start_ip.split(".")))
   end = list(map(int, end_ip.split(".")))
   temp = start
   ip_range = []

   ip_range.append(start_ip)
   while temp != end:
      start[3] += 1
      for i in (3, 2, 1):
         if temp[i] == 256:
            temp[i] = 0
            temp[i-1] += 1
      ip_range.append(".".join(map(str, temp)))

   return ip_range



def get_zone_members_list(zone_member):
    z_members = tree.xpath(".//zone/entry[@name='"+ zone_member +"']/network/layer3/member/text()")

    return z_members

def get_zone_member_info(member):

    ae_members = []

    if re.match("^ae",member):
        ae_members = tree.xpath("/config/devices/entry/network/interface/aggregate-ethernet/entry/"
                                "layer3/units/entry[@name='"+ member +"']/ip/entry/@name")

    return ae_members

def get_address_group_member(vsys,members):
        agms = tree.xpath("/config/devices/entry/vsys/entry[@name='"+vsys+
                          "']/address-group/entry[@name='" + members + "']//member/text()")

        return agms

def get_address_member(vsys,member):
    if re.match("any",member):
        return ['any']
    adm = tree.xpath("/config/devices/entry/vsys/entry[@name='"+vsys+
                     "']/address/entry[@name='" + member + "']/ip-netmask/text()")
    if len(adm) == 0:
        adm = tree.xpath("/config/devices/entry/vsys/entry[@name='"+vsys+
                         "']/address/entry[@name='" + member + "']/ip-range/text()")
        #if len(adm) != 0:
        #    start_ip, end_ip = adm[0].split("-")
        #    adm = ipRange(start_ip, end_ip)

    return adm



print(
    "'vsys';'name';'description';'from';'to';'source';'Warn_s','destination','Warn_d';"
    "'application';'action';'disabled';'log-start';log-stop")



vsys_list = tree.xpath("/config/devices/entry/vsys/entry/@name")

#vsys_number = len(vsys_list)

#vsys_id=1

#print(vsys_list, vsys_number)

for vsys_id in vsys_list:

    policy_root =  "/config/devices/entry/vsys/entry[@name='"+vsys_id+"']/rulebase/security/rules"

    policies_number = tree.xpath(policy_root+"/entry")

    pn = (len(policies_number))
    policy_n = 1


    while policy_n <= pn:
        policy_name = tree.xpath(
            policy_root+"/entry[" + str(policy_n) + "]/@name")


        policies_from = tree.xpath(
            policy_root+"/entry[" + str(policy_n) + "]/from/member/text()")

        policies_to = tree.xpath(
            policy_root+"/entry[" + str(policy_n) + "]/to/member/text()")

        sources = tree.xpath(
            policy_root+"/entry[" + str(policy_n) + "]/source/member/text()")


        destinations = tree.xpath(
            policy_root+"/entry[" + str(policy_n) + "]/destination/member/text()")

        applications = tree.xpath(
            policy_root+"/entry[" + str(policy_n) + "]/application/member/text()")

        actions = tree.xpath(
            policy_root+"/entry[" + str(policy_n) + "]/action/text()")

        descriptions = tree.xpath(
            policy_root+"/entry[" + str(policy_n) + "]/description/text()")

        disabled = tree.xpath(
            policy_root+"/entry[" + str(policy_n) + "]/disabled/text()")

        log_start = tree.xpath(
            policy_root+"/entry[" + str(policy_n) + "]/log-start/text()")

        log_stop = tree.xpath(
            policy_root+"/entry[" + str(policy_n) + "]/log-stop/text()")


        csvdict = {}

        csvdict["vsys"] = vsys_id


        csvdict["name"] = policy_name
        # for name in policy_name:
        #     print("{} > {}".format(vsys_id,name))

        csvdict["description"]=descriptions
        # for description in descriptions:
        #     print("|-# {}".format(description))

        for from_ in policies_from:
            #if re.match("any",from_ ):
            #    mdf=["any"]
            #    continue
            # print("  |-+> {}".format(from_))
            zmf = get_zone_members_list(from_)
            for zmf_ in zmf:
                mdf = get_zone_member_info(zmf_)
                # print("  |   |<- {}".format(zmf_))
                # for mdf_ in mdf:
                #      print("  |   |   |-> {}".format(mdf_))

        csvdict["from"] =  policies_from
        csvdict["from_net"] =  mdf

        for to_ in policies_to:
            #if re.match("any",to_ ):
            #    mdt=["any"]
            #    continue
            # print("  |-+< {}".format(to_))
            zmt = get_zone_members_list(to_)
            for zmt_ in zmt:
                mdt = get_zone_member_info(zmt_)
                # print("  |   |<- {}".format(zmt_))
                # for mdt_ in mdt:
                #    print("  |   |   |<- {}".format(mdt_))

        csvdict["to"] =  policies_to
        csvdict["to_net"] =  mdt

        source_h = []
        for source in sources:
            #if re.match("any",source):
            #    source_h.append("any")
            #    continue
            # print("  |-> {}".format(source))
            agms = get_address_group_member(vsys_id,source)
            if len(agms) == 0:
                Y = get_address_member(vsys_id,source)
                for Y_ in Y:
                    # print("  | |-> {}".format(Y_))
                    source_h.append(Y_)
            else:
                for agms_ in agms:
                    V=get_address_member(vsys_id,agms_)
                    #print("  | |-> {}".format(V))
                    for agms__ in V:
                        # print("  | |-> {}".format(agms__))
                        source_h.append(agms__)

        csvdict['warn_s'] = ''
        for c in source_h:
            if re.search('.*/(8/16)',c):
                csvdict['warn_s'] = "X"

        csvdict["source"] = sources

        destination_h = []
        for destination in destinations:
            #if re.match("any",destination):
            #    source_h.append("any")
            #    continue
            # print("  |<- {}".format(destination))
            agmd = get_address_group_member(vsys_id,destination)
            if len(agmd) == 0:
                X = get_address_member(vsys_id,destination)
                for X_ in X:
                    # print("  | |<- {}".format(X_))
                    destination_h.append(X_)
            else:
                for agmd_ in agmd:
                    W=get_address_member(vsys_id,agmd_)
                    for agmd__ in W:
                        # print("  | |<- {}".format(agmd__))
                        destination_h.append(agmd__)

        csvdict['warn_d']=''
        for c in destination_h:
            if re.search('.*/(8|16)',c):
                csvdict['warn_d'] = "X"

        csvdict["destination"] = destinations

        # for application in applications:
        #     print("  |-[] {}".format(application))

        csvdict["application"] = applications


        # for action in actions:
        #     print("  |-* {}".format(action))

        csvdict["action"] = actions



        # for disabled_ in disabled:
        #     print("  |-X {}".format(disabled_))

        csvdict["disabled"] = disabled

        # for log_start_ in log_start:
        #     print("  |-$ {}".format(log_start_))

        csvdict["log-start"] = log_start

        # for log_stop_ in log_stop:
        #     print("  |-% {}".format(log_stop_))

        csvdict["log-stop"] = log_stop

    # print csv
        to_list = []
        for to__ in csvdict["to_net"]:
            to_list.append(to__)
        for to__ in csvdict["source"]:
            to_list.append(to__)

        from_list = []
        for from__ in csvdict["from_net"]:
            to_list.append(from__)
        for from__ in csvdict["destination"]:
            from_list.append(from__)


        #for zf in csvdict["from"]:
        #    for zt in csvdict["to"]:
        for src in to_list:
            for dst in from_list:
                for app in csvdict["application"]:
                    print("'{}';'{}';'{}';'{}';'{}';'{}';'{}';'{}';'{}';'{}';'{}';'{}';".format(csvdict['vsys'],\
                                             csvdict['name'],csvdict["description"],csvdict["from"],csvdict["to"],\
                                             src,csvdict["warn_s"],dst,csvdict["warn_d"],\
                                             app,csvdict["action"],csvdict["disabled"],\
                                             csvdict["log-start"],csvdict["log-stop"]))


        #print(csvdict)

        policy_n += 1