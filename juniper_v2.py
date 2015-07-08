#!/usr/bin/python3

__author__ = 'Karim AYARI'

from lxml import etree
from io import StringIO
import re


class Juniper:
    """ A Juniper rule parser """

    def __init__(self, name):
        self.name = name
        self.policies_root_count = 0
        self.PoliciesRoot = ""
        self.AddressbookRoot = ""
        self.ApplicationsRoot = ""
        self.tree = ""
        self.data = {}

    @staticmethod
    def csvheader():
        print(
            "'name';'from-zone-name';'to-zone-name';'source-address';'destination-address';"
            "'application';'action';'inactive';'log'")

        return 0

    def csvline(self):
        for d in self.data['RuleDestinationAddresses']:
            for s in self.data['RuleSourceAddresses']:
                for p in self.data['RuleApplications']:
                    print("'{}';'{}';'{}';'{}';'{}';'{}';'{}';'{}';'{}'".format(self.data['RuleName'],
                                                                                self.data['PolicyFrom'],
                                                                                self.data['PolicyTo'], s,
                                                                                d, p, self.data['RuleAction'],
                                                                                self.data['RuleActivity'],
                                                                                self.data['RuleLog']))
        return None

    @staticmethod
    def loadxml(filename):
        global tree
        file = open(filename, 'r')
        xml = file.read()
        file.close()
        tree = etree.parse(StringIO(xml))
        return True

    def getPolicyRootNumber(self):
        policies_root_number = tree.xpath("count(" + self.PoliciesRoot + ")")
        return policies_root_number

    def getRulesNumber(self, PolicyIndex):
        policy_number = tree.xpath("count(" + self.PoliciesRoot + "[" + str(PolicyIndex) + "]/policy)")
        return policy_number

    def getPolicyFrom(self, PolicyIndex):
        policies_from = tree.xpath(self.PoliciesRoot + "[" + str(PolicyIndex) + "]/from-zone-name/text()")
        return policies_from

    def getPolicyTo(self, PolicyIndex):
        policies_to = tree.xpath(self.PoliciesRoot + "[" + str(PolicyIndex) + "]/to-zone-name/text()")
        return policies_to

    def getRuleName(self, PolicyIndex, RuleIndex):
        policy_name = tree.xpath(
            self.PoliciesRoot + "[" + str(PolicyIndex) + "]/policy[" + str(
                RuleIndex) + "]/name/text()")
        return policy_name

    def getRuleActivity(self, PolicyIndex, RuleIndex):
        activity = tree.xpath(
            self.PoliciesRoot + "[" + str(PolicyIndex) + "]/policy[" + str(
                RuleIndex) + "]/@inactive")
        if len(activity) == 0:
            activity = ['active']
        return activity

    def getRuleAction(self, PolicyIndex, RuleIndex):
        actions = tree.xpath("boolean(" + self.PoliciesRoot + "[" + str(PolicyIndex) +
                             "]/policy[" + str(RuleIndex) + "]/then/permit)")
        if actions:
            actions = "permit"
        else:
            actions = "deny"
        return actions

    def getRuleLog(self, PolicyIndex, RuleIndex):
        logs = tree.xpath(self.PoliciesRoot + "[" + str(PolicyIndex) + "]/policy[" + str(
            RuleIndex) + "]/then/log/*")
        logFlags = []
        for log in logs:
            logFlags.append(log.tag)
        return logFlags

    def getRuleMembers(self, PolicyIndex, RuleIndex, Side):
        AddressesMembers = tree.xpath(
            self.PoliciesRoot + "[" + str(PolicyIndex) + "]/policy[" + str(RuleIndex) + "]/match/" + Side)
        members = []
        for member in AddressesMembers:
            members.append(member.text)
        return members

    @staticmethod
    def isAddressSet(member):
        isaddressset = tree.xpath("boolean(.//address-set[name='" + member + "'])")
        return isaddressset

    @staticmethod
    def isAddress(member):
        isaddress = tree.xpath("boolean(.//address[name='" + member + "'])")
        return isaddress

    def getRuleAddressBookMembers(self, Policy, member):
        addressmembers = tree.xpath(
            self.AddressbookRoot + "/security-zone[name = '" + Policy + "']/address-book/address-set[name = '" +
            member + "']/address/name")
        f = []

        for x in addressmembers:
            f.append(x.text)

        return f

    def getAllObjectMembers(self, Policy, RuleMembers):
        members = []
        for RuleMember in RuleMembers:
            if re.match("any", RuleMember):
                members.append("any")
            if self.isAddress(RuleMember):
                members.append(RuleMember)
            if self.isAddressSet(RuleMember):
                for x in self.getRuleAddressBookMembers(Policy, RuleMember):
                    members.append(x)
        return members

    def getAddress(self, Policy, members):
        f = []
        for member in members:
            if re.match("any", member):
                f.append("any")
                continue
            address = tree.xpath(
                self.AddressbookRoot + "/security-zone[name = '" + Policy
                + "']/address-book/address[name = '" + member + "']/ip-prefix/text()")
            f.append(address[0])

        return f

    def getRuleApplications(self, PolicyIndex, RuleIndex):
        applications = tree.xpath(
            self.PoliciesRoot + "[" + str(PolicyIndex) + "]/policy[" + str(
                RuleIndex) + "]/match/application")

        apps = []

        for app in applications:
            apps.append(app.text)

        return apps

    @staticmethod
    def isApplicationSet(AppName):
        isapplicationset = tree.xpath("boolean(.//application-set[name='" + AppName + "'])")
        return isapplicationset

    @staticmethod
    def isApplication(AppName):
        isapplication = tree.xpath("boolean(.//application[name='" + AppName + "'])")
        return isapplication

    @staticmethod
    def getApplicationPort(AppName):
        if re.match("any", AppName):
            return "any"
        applicationport = tree.xpath(".//application[name='" + AppName + "']/destination-port/text()")

        if len(applicationport) == 0:
            """ Check term """
            applicationport = [AppName]

        applicationproto = tree.xpath(".//application[name='" + AppName + "']/protocol/text()")
        if len(applicationproto) == 0:
            """ Check term """
            applicationproto = ['NA']

        result = applicationport[0] + "/" + applicationproto[0]

        return result


def main():
    junos = Juniper('FW')

    # junos.loadxml("E:/PY/temp/Junos/THSRAHNUNFW01P.xml")
    junos.loadxml("/run/media/karim/Lexar/PY/temp/Junos/THSRAHNUNFW01P.xml")
    junos.PoliciesRoot = "/rpc-reply/configuration/security/policies/policy"
    junos.AddressbookRoot = "/rpc-reply/configuration/security/zones"
    junos.ApplicationsRoot = "/rpc-reply/configuration/applications"

    PolicyRootNumber = junos.getPolicyRootNumber()

    PolicyRootCounter = 1

    while PolicyRootCounter <= PolicyRootNumber:
        PolicyFrom = junos.getPolicyFrom(PolicyRootCounter)
        PolicyTo = junos.getPolicyTo(PolicyRootCounter)
        rules_number = junos.getRulesNumber(PolicyRootCounter)
        RulesCounter = 1
        while RulesCounter <= rules_number:
            RuleName = junos.getRuleName(PolicyRootCounter, RulesCounter)
            RuleActivity = junos.getRuleActivity(PolicyRootCounter, RulesCounter)
            RuleAction = junos.getRuleAction(PolicyRootCounter, RulesCounter)
            RuleLog = junos.getRuleLog(PolicyRootCounter, RulesCounter)
            RuleSourceMembers = junos.getRuleMembers(PolicyRootCounter, RulesCounter, "source-address")
            RuleDestinationMembers = junos.getRuleMembers(PolicyRootCounter, RulesCounter, "destination-address")

            src = junos.getAllObjectMembers(PolicyFrom[0], RuleSourceMembers)
            dst = junos.getAllObjectMembers(PolicyTo[0], RuleDestinationMembers)

            RuleSourceAddresses = junos.getAddress(PolicyFrom[0], src)
            RuleDestinationAddresses = junos.getAddress(PolicyTo[0], dst)

            RuleApplications = junos.getRuleApplications(PolicyRootCounter, RulesCounter)

            junos.data['PolicyFrom'] = PolicyFrom
            junos.data['PolicyTo'] = PolicyTo
            junos.data['RuleName'] = RuleName
            junos.data['RuleActivity'] = RuleActivity
            junos.data['RuleAction'] = RuleAction
            junos.data['RuleLog'] = RuleLog
            junos.data['RuleSourceAddresses'] = RuleSourceAddresses
            junos.data['RuleDestinationAddresses'] = RuleDestinationAddresses
            junos.data['RuleApplications'] = RuleApplications

            junos.csvline()

            RulesCounter += 1

        PolicyRootCounter += 1


if __name__ == "__main__":
    main()
