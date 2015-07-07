#!/usr/bin/python3

__author__ = 'Karim AYARI'

from lxml import etree
from io import StringIO
import argparse


class Juniper:
    """ A Juniper rule parser """

    def __init__(self, name):
        self.name = name
        self.policies_root_count = 0
        self.PoliciesRoot = ""
        self.AddressbookRoot = ""
        self.tree = ""

    def csvheader(self):
        print(
            "'name';'from-zone-name';'to-zone-name';'source-address';'destination-address';"
            "'application';'action';'inactive';'log'")
        return True

    def loadxml(self,filename):
        global tree
        file = open(filename, 'r')
        xml = file.read()
        file.close()
        tree = etree.parse(StringIO(xml))
        return True

    def getPolicyRootNumber(self):
        policies_root_number = tree.xpath("count("+self.PoliciesRoot+")")
        return policies_root_number

    def getRulesNumber(self,PolicyIndex):
        policy_number = tree.xpath("count("+self.PoliciesRoot+"[" + str(PolicyIndex) + "]/policy)")
        return policy_number

    def getPolicyFrom(self,PolicyIndex):
        policies_from = tree.xpath(
        self.PoliciesRoot+"[" + str(PolicyIndex) + "]/from-zone-name/text()")
        return policies_from

    def getPolicyTo(self,PolicyIndex):
        policies_to = tree.xpath(self.PoliciesRoot+"[" + str(PolicyIndex) + "]/to-zone-name/text()")
        return policies_to

    def getRuleName(self,PolicyIndex,RuleIndex):
        policy_name = tree.xpath(
            self.PoliciesRoot+"[" + str(PolicyIndex) + "]/policy[" + str(
                RuleIndex) + "]/name/text()")
        return policy_name

    def getRuleActivity(self,PolicyIndex,RuleIndex):
        activity = tree.xpath(
            self.PoliciesRoot+"[" + str(PolicyIndex) + "]/policy[" + str(
                RuleIndex) + "]/@inactive")
        if len(activity) == 0:
            activity = ['active']
        return activity

    def getRuleAction(self,PolicyIndex,RuleIndex):
        actions = tree.xpath("boolean("+
            self.PoliciesRoot+"[" + str(PolicyIndex) + "]/policy[" + str(
                RuleIndex) + "]/then/permit)")
        if actions == True:
            actions = "permit"
        else:
            actions = "deny"
        return actions

    def getRuleLog(self,PolicyIndex,RuleIndex):
        logs = tree.xpath(self.PoliciesRoot+"[" + str(PolicyIndex) + "]/policy[" + str(
            RuleIndex) + "]/then/log/*")
        logFlags = []
        for log in logs:
            logFlags.append(log.tag)
        return logFlags

    def getRuleMembers(self,PolicyIndex,RuleIndex,Side):
        AddressesMembers = tree.xpath(
            self.PoliciesRoot+"[" + str(PolicyIndex) + "]/policy[" + str(RuleIndex) + "]/match/" + Side )
        members = []
        for member in AddressesMembers:
            members.append(member.text)
        return members

    def getRuleAddressBookMembers(self,RuleName,members):
        for addressbook in members:
            #print(self.AddressbookRoot+"/security-zone[name = '" + RuleName[0] + "']/address-book/address-set[name = '" + addressbook + "']/address/name")
            #AddressMembers = tree.xpath("boolean("+self.AddressbookRoot+"/security-zone[name = '" + RuleName[0] + "']/address-book/address-set[name = '" + addressbook + "']/address/name)")
            print(self.AddressbookRoot+"/security-zone[name = '" + RuleName[0] + "']")
            AddressMembers = tree.xpath("boolean("+self.AddressbookRoot+"/security-zone[name = '" + RuleName[0] + "'])")
        return AddressMembers





junos = Juniper('firewall')

junos.loadxml("E:/PY/temp/Junos/THSRAHNUNFW01P.xml")
junos.PoliciesRoot="/rpc-reply/configuration/security/policies/policy"
junos.AddressbookRoot="/rpc-reply/configuration/security/zones"

#security-zone[@name = '" + zone
#             + "']/address-book/address-set[name = '" + address_ + "']/address/name/text()")"

PolicyRootNumber = junos.getPolicyRootNumber()

PolicyRootCounter = 1

while PolicyRootCounter <= PolicyRootNumber:
    PolicyFrom = junos.getPolicyFrom(PolicyRootCounter)
    PolicyTo = junos.getPolicyTo(PolicyRootCounter)
    #print("{} {}".format(PolicyFrom,PolicyTo))
    rules_number = junos.getRulesNumber(PolicyRootCounter)
    rules_counter = 1
    while rules_counter <= rules_number:
        RuleName = junos.getRuleName(PolicyRootCounter,rules_counter)
        RuleActivity = junos.getRuleActivity(PolicyRootCounter,rules_counter)
        RuleAction = junos.getRuleAction(PolicyRootCounter,rules_counter)
        RuleLog = junos.getRuleLog(PolicyRootCounter,rules_counter)
        RuleSourceMembers = junos.getRuleMembers(PolicyRootCounter,rules_counter,"source-address")
        RuleDestinationMembers = junos.getRuleMembers(PolicyRootCounter,rules_counter,"destination-address")
        RuleSourceAddresses = junos.getRuleAddressBookMembers(RuleName,RuleSourceMembers)

        #print("  | {}".format(RuleName))
        #print("  | {}".format(RuleActivity))
        #print("  | {}".format(RuleAction))
        #print("  | {}".format(RuleLog))
        #print("    | {}".format(RuleSourceMembers))
        print("    | {}".format(RuleSourceAddresses))
        #print("  | {}".format(RuleDestinationMembers))

        rules_counter = rules_counter + 1

    PolicyRootCounter = PolicyRootCounter + 1










