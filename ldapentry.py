#!/usr/bin/env python
# coding: utf-8
#
# Authorization module software developed for the staircase door access control at Hackerspace Kraków.
# Copyright (C) 2017 Jakub Kramarz
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

from auth_plugin import EnterpriseAuthPlugin, main

import sys
import syslog
import time
import ldap3

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser

from constants import *

config_file = ConfigParser.RawConfigParser()
config_file.read(['ldap.ini'])

hosturl = config_file.get(CONFIG_SECTION_LDAP, CONFIG_LDAP_URL)
binddn = config_file.get(CONFIG_SECTION_LDAP, CONFIG_LDAP_BINDDN)
bindpw = config_file.get(CONFIG_SECTION_LDAP, CONFIG_LDAP_BINDPW)
search_base = config_file.get(CONFIG_SECTION_LDAP, CONFIG_LDAP_SEARCH_BASE)

hsowicz_group = 'cn=members,cn=groups,cn=accounts,dc=at,dc=hskrk,dc=pl'
ryjek_group = 'cn=ryjek,cn=groups,cn=accounts,dc=at,dc=hskrk,dc=pl'
ryjek_access = [
    'outdoor',
    'indoor',
    'magazynek'
]

syslog.openlog("zamek_auth", 0, 128)

def log(txt):
    syslog.syslog(txt.encode("utf-8"))
    print(txt.encode("utf-8"))

def get_user_by_card(connection, card_number):
    result = connection.search(
        search_base=search_base,
        search_filter="(uniqueCardId=%s)" % (card_number),
        attributes=[
            'uid',
            'memberOf',
            'membershipExpiration'
        ]
    )
    if len(connection.entries) == 1:
        return connection.entries[0]
    else:
        return None

def get_user_by_uid(connection, uid):
    result = connection.search(
        search_base=search_base,
        search_filter="(uid=%s)" % (uid),
        attributes=[
            'uid',
            'memberOf',
            'membershipExpiration'
        ]
    )
    if len(connection.entries) == 1:
        return connection.entries[0]
    else:
        return None

def unix_epoch_day():
    return int(time.time()) / (24 * 60 * 60)

def check_ryjek(connection):
    entry = get_user_by_uid(connection, 'wbielak')
    if entry:
        return check_hsowicz(entry)
    else:
        return False

def check_hsowicz(entry):
    expiration = int(entry.membershipExpiration.value)
    return expiration >= unix_epoch_day()


def check_card(zone, card_number):
    server = ldap3.Server(hosturl)
    connection = ldap3.Connection(
        server, auto_bind=True, client_strategy=ldap3.SYNC,
        user=binddn, password=bindpw,
        authentication=ldap3.SIMPLE, check_names=True
    )

    entry = get_user_by_card(connection, card_number)

    name = None
    result = False

    if entry:
        name = entry.uid.value
        if hsowicz_group in entry.memberOf:
            result |= check_hsowicz(entry)
        if ryjek_group in entry.memberOf and zone in ryjek_access:
            result |= check_ryjek(connection)

    return name, result


class LDAPAuthPlugin(EnterpriseAuthPlugin):
    def __init__(self):
        super(LDAPAuthPlugin, self).__init__()
        self.name = 'LDAP connector'

    def on_cardread(self, zoneid, cardcode):
        name, result = check_card(zoneid, cardcode)
        if not name:
            log('rejected unknown card %s for zone %s' % (cardcode, zoneid))
            self.reject(zoneid)
        else:
            if result:
                log('accepted card %s (%s) for zone %s' % (cardcode, name, zoneid))
                self.accept(zoneid)
            else:
                log('rejected card %s (%s) for zone %s' % (cardcode, name, zoneid))
                self.reject(zoneid)

if __name__ == '__main__':
    main(LDAPAuthPlugin)
