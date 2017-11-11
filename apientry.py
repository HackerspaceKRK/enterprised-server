#!/usr/bin/env python
# coding: utf-8
#
# Authorization module software developed for the staircase door access control at Hackerspace Kraków.
# Copyright (C) 2016 Tadeusz Magura-Witkowski
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
sys.path.append("/opt/skladki")
import skladki_lib

syslog.openlog("zamek_auth_plugin", 0, 128)

def log(txt):
	syslog.syslog(txt.encode("utf-8"))
	print(txt.encode("utf-8"))

def check_card_api(card_number):
	api = skladki_lib.SkladkiAPI()
	api.connect()
	user = api.getUserByCard(card_number)
	if user is None:
		log('No card in database')
		return False

	if user.active:
		log(u"User {0} auth succeed".format(user.getLongName()))
		return True
	else:
		log(u"User {0} card is not active".format(user.getLongName()))
		return False

def check_card(card_number):
	if check_card_api(card_number):
		return True

	with file('karty.txt', 'r') as f:
		for line in f:
			number = line.strip()

			if len(number) == 0:
				continue

			if number[0] == ';':
				continue

			number, comment = map(lambda x: x.strip(), number.split(':'))

			if card_number == number:
				return True

	return False


class SkladkiAPIAuthPlugin(EnterpriseAuthPlugin):
	def __init__(self):
		super(SkladkiAPIAuthPlugin, self).__init__()
		self.name = 'Connector for old system'

	def on_cardread(self, zoneid, cardcode):
		retval = check_card(cardcode)

		if retval:
			self.accept(zoneid)
		else:
			self.reject(zoneid)


if __name__ == '__main__':
	main(SkladkiAPIAuthPlugin)