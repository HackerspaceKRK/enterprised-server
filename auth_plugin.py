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

import json
import logging
import argparse
import ConfigParser

import paho.mqtt.client as paho

from constants import *


class EnterpriseAuthPlugin(object):
	def __init__(self):
		super(EnterpriseAuthPlugin, self).__init__()
		
	# def on_keypress(self, zoneid, keycode):
	# 	pass

	# def on_cardread(self, zoneid, cardcode):
	# 	pass

	# def on_tamper(self, zoneid):
	# 	pass

	# def on_pingtimeout(self):
	# 	pass

	# def on_watchdog(self):
	# 	pass

	# def on_action(self, zoneid, action):
	# 	pass


	# following ones will be patched by AuthPluginRunner
	def accept(self, zoneid):
		pass

	def reject(self, zoneid):
		pass



class AuthPluginRunner(object):
	def __init__(self, config, plugin):
		super(AuthPluginRunner, self).__init__()
		self._config = config
		self._plugin = plugin


		plugin.accept = self._plugin_do_accept
		plugin.reject = self._plugin_do_reject

	def _plugin_keypress(self, info, payload):
		self._plugin.on_keypress(info[0], payload)

	def _plugin_cardread(self, info, payload):
		self._plugin.on_cardread(info[0], payload)

	def _plugin_tamper(self, info, payload):
		self._plugin.on_tamper(info[0])

	def _plugin_watchdog(self, info, payload):
		self._plugin.on_watchdog()

	def _plugin_timeout(self, info, payload):
		self._plugin.on_timeout()

	def _plugin_do_accept(self, zoneid):
		self._client.publish('enterprised/reader/{0}/action'.format(zoneid), 'accept')

	def _plugin_do_reject(self, zoneid):
		self._client.publish('enterprised/reader/{0}/action'.format(zoneid), 'reject')

	def _plugin_action(self, info, payload):
		self._plugin.on_action(info[0], payload)
		

	def _mqtt_incoming(self, client, userdata, message):
		splitted = message.topic.split('/')

		msg_sender = splitted[2]
		msg_type = splitted[3]
		
		ACTION_MAPPING = {
			EVENT_KEYPRESS: self._plugin_keypress,
			EVENT_CARDREAD: self._plugin_cardread,
			EVENT_TAMPER: self._plugin_tamper,
			EVENT_TIMEOUT: self._plugin_timeout,
			EVENT_WATCHDOG: self._plugin_watchdog,
			EVENT_ACTION: self._plugin_action,
		}

		try:
			ACTION_MAPPING[msg_type](splitted[2:], message.payload)
		except KeyError:
			logging.warning('MQTT unknown event %s', msg['event'])

	def _request_signal(self, name, path):
		try:
			getattr(self._plugin, name)
			self._client.subscribe(path)
		except AttributeError:
			pass

	def _mqtt_connected(self, client, userdata, flags, rc):
		self._request_signal('on_keypress', 'enterprised/reader/+/keypress')
		self._request_signal('on_cardread', 'enterprised/reader/+/cardread')
		self._request_signal('on_tamper', 'enterprised/reader/+/tamper')

		self._request_signal('on_pingtimeout', 'enterprised/system')
		self._request_signal('on_watchdog', 'enterprised/system')

		self._request_signal('on_action', 'enterprised/reader/+/action')


	def _do_mqtt(self):
		self._client = paho.Client()
		self._client.on_message = self._mqtt_incoming
		self._client.on_connect = self._mqtt_connected
		self._client.connect(self._config.mqtt_host, port=self._config.mqtt_port)
		self._client.loop_forever()

	def run(self):
		self._do_mqtt()


class MQTTConfig(object):
	def __init__(self, mqtt_host, mqtt_port):
		self.mqtt_host = mqtt_host
		self.mqtt_port = mqtt_port


def main(plugin_class):
	plugin = plugin_class()

	parser = argparse.ArgumentParser(description='Enterprise RFID Unique (EM4100) Access Controller Plugin - {0}'.format(plugin.name))
	parser.add_argument('--log', default='WARNING', choices=('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'), help='log level')
	args = parser.parse_args()

	numeric_level = getattr(logging, args.log.upper(), None)
	if not isinstance(numeric_level, int):
		raise ValueError('Invalid log level: %s' % loglevel)
	logging.basicConfig(level=numeric_level)

	config_file = ConfigParser.RawConfigParser()
	config_file.read(['config.ini', 'localconfig.ini'])

	config = MQTTConfig(
		mqtt_host=config_file.get(CONFIG_SECTION_MQTT, CONFIG_MQTT_HOST),
		mqtt_port=config_file.getint(CONFIG_SECTION_MQTT, CONFIG_MQTT_PORT))

	enterprise_driver = AuthPluginRunner(config=config, plugin=plugin)
	enterprise_driver.run()

if __name__ == '__main__':
	print 'Implement your own plugin, see example: pinentry.py'