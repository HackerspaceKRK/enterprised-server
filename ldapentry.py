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
import ConfigParser

from constants import *

config_file = ConfigParser.RawConfigParser()
config_file.read(['ldap.ini'])

hosturl = config_file.get(CONFIG_SECTION_LDAP, CONFIG_LDAP_URL)
binddn = config_file.get(CONFIG_SECTION_LDAP, CONFIG_LDAP_BINDDN)
bindpw = config_file.get(CONFIG_SECTION_LDAP, CONFIG_LDAP_BINDPW)
search_base = config_file.get(CONFIG_SECTION_LDAP, CONFIG_LDAP_SEARCH_BASE)

syslog.openlog("zamek_auth", 0, 128)


def log(txt):
    syslog.syslog(txt.encode("utf-8"))
    print(txt.encode("utf-8"))


def check_card(zone, card_number):
    unix_epoch_day = int(time.time()) / (24 * 60 * 60)

    server = ldap3.Server(hosturl)
    connection = ldap3.Connection(
        server, auto_bind=True, client_strategy=ldap3.SYNC,
        user=binddn, password=bindpw,
        authentication=ldap3.SIMPLE, check_names=True
    )

    result = connection.search(
        search_base=search_base,
        search_filter="(&(uniqueCardID=%s)(shadowInactive>=%d))" % (card_number, unix_epoch_day)
    )

    if len(connection.entries) == 1:
        entry = connection.entries[0]
        uid = entry.entry_dn.split(',')[0].split('=')[1]
        log("%s: %s is comming!" % (zone, uid))
        return True
    else:
        return False


class LDAPAuthPlugin(EnterpriseAuthPlugin):
    def __init__(self):
        super(LDAPAuthPlugin, self).__init__()
        self.name = 'LDAP connector'

    def on_cardread(self, zoneid, cardcode):
        retval = check_card(zoneid, cardcode)

        if retval:
            self.accept(zoneid)
        else:
            self.reject(zoneid)


if __name__ == '__main__':
    main(LDAPAuthPlugin)
