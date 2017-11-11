#!/usr/bin/env python3
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

import syslog

from auth_plugin import EnterpriseAuthPlugin, main

syslog.openlog("zamek_auth", 0, 128)

def log(txt):
	syslog.syslog(txt.encode("utf-8"))
	print(txt.encode("utf-8"))


class LoggingPlugin(EnterpriseAuthPlugin):
	def __init__(self):
		super(LoggingPlugin, self).__init__()
		self.name = 'Plugin that log everything to syslog'

	def on_action(self, zoneid, action):
		log('{}: {}'.format(zoneid, action))

	def on_cardread(self, zoneid, cardcode):
		log('{}: scan: {}'.format(zoneid, cardcode))

if __name__ == '__main__':
	main(LoggingPlugin)