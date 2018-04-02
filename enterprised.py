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


'''
New enterprise RFID authentication controller

Copyright (C) 2016 Tadeusz Magura-Witkowski


This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
'''

import os
import json
import serial
import logging
import argparse
import threading
import ConfigParser

import paho.mqtt.client as paho

from constants import *


class EnterpriseDriverConfig(object):
    def __init__(self, serial_url, serial_speed, mqtt_host, mqtt_port):
        super(EnterpriseDriverConfig, self).__init__()
        self.serial_url = serial_url
        self.serial_speed = serial_speed
        self.mqtt_host = mqtt_host
        self.mqtt_port = mqtt_port


class EnterpriseDriver(object):
    PING_TIMEOUT_THRESHOLD = 5

    def __init__(self, config):
        super(EnterpriseDriver, self).__init__()
        self._config = config

    def _connect_serial(self):
        self._ser = serial.serial_for_url(self._config.serial_url, self._config.serial_speed)

    def _send_to_io(self, message):
        logging.debug('Sending: %s', message)

        self._ser.write(message + '\n');

    # TODO: replace with functools..
    def _send_ping(self):
        PING_PACKET = '*P#'

        self._send_to_io(PING_PACKET)

    def _test_serial(self):
        PING_REPLY_PACKET = '*P'

        self._ser.timeout = 1

        self._send_ping()

        response = self._ser.readline().strip()

        if response != PING_REPLY_PACKET:
            logging.critical('Invalid or no reply from IO board')

            exit(0)

        logging.info('IO board has replied to ping, looks like everything is okay')

    def _mqtt_incoming_Accept(self, zone):
        logging.info('Accept: Z: %s', zone)
        self._ser.write('*A#{0}\n'.format(zone))

    def _mqtt_incoming_Reject(self, zone):
        logging.info('Reject: Z: %s', zone)
        self._ser.write('*R#{0}\n'.format(zone))

    def _mqtt_incoming(self, client, userdata, message):
        msg = json.loads(message.payload)

        zone = int(msg['zone'])
        action = msg['action']

        ACTION_MAPPING = {
            'accept': self._mqtt_incoming_Accept,
            'reject': self._mqtt_incoming_Reject
        }

        try:
            ACTION_MAPPING[action](zone)
        except KeyError:
            logging.warning('MQTT has requested unknown action type: \'%s\'', action)

    def _mqtt_connected(self, client, userdata, flags, rc):
        client.subscribe('enterprised/reader/+')

    def _connect_mqtt(self):
        self._client = paho.Client()
        self._client.on_message = self._mqtt_incoming
        self._client.on_connect = self._mqtt_connected
        self._client.will_set('enterprised/system', json.dumps({
            'event': EVENT_SHUTDOWN
        }))
        self._client.connect(self._config.mqtt_host, port=self._config.mqtt_port)
        self._client.loop_start()

    def _io_to_mqtt_KeyPress(self, message):
        # zone, keycode

        zone = int(message[0])
        keycode = int(message[1])

        logging.info('KeyPress: Z: %s C: %s', zone, keycode)

        return ('enterprised/reader/{0}/keypress'.format(zone), json.dumps({
            'event': EVENT_KEYPRESS,
            'zone': zone,
            'keycode': keycode,
        }))

    def _io_to_mqtt_CardRead(self, message):
        # zone, cardcode

        zone = int(message[0])
        cardcode = int(message[1])

        logging.info('CardRead: Z: %s C: %s', zone, cardcode)

        return ('enterprised/reader/{0}/cardread'.format(zone), json.dumps({
            'event': EVENT_CARDREAD,
            'zone': zone,
            'cardcode': cardcode,
        }))

    def _io_to_mqtt_Tamper(self, message):
        # zone

        zone = int(message[0])

        logging.info('Tamper: Z: %s', zone)

        return ('enterprised/reader/{0}/tamper'.format(zone), json.dumps({
            'event': EVENT_TAMPER,
            'zone': zone
        }))

    def _io_to_mqtt_Watchdog(self, message):
        logging.warning('IO board has been reseted by watchdog')

        return ('enterprised/system', json.dumps({
            'event': EVENT_WATCHDOG
        }))

    def _io_to_mqtt_PingReply(self, message):
        logging.debug('Ping reply')

        self._ping_sent_without_response = 0

    def _io_to_mqtt(self, message):
        action = message[0]

        ACTION_MAPPING = {
            'K': self._io_to_mqtt_KeyPress,
            'C': self._io_to_mqtt_CardRead,
            'T': self._io_to_mqtt_Tamper,
            'P': self._io_to_mqtt_PingReply,
            'W': self._io_to_mqtt_Watchdog,
        }

        message = message[1:]

        try:
            return ACTION_MAPPING[action](message)
        except KeyError:
            logging.warning('IO board has sent unknown action type: \'%s\'', action)

    def _process_io2mqtt(self):
        self._ser.timeout = 5
        self._ping_sent_without_response = 0

        while True:
            message_from_io = self._ser.readline().strip()

            if len(message_from_io) == 0:
                self._send_ping()

                self._ping_sent_without_response += 1

                if self._ping_sent_without_response > EnterpriseDriver.PING_TIMEOUT_THRESHOLD:
                    logging.warning('Ping timeout')
                    self._client.publish('enterprised/system', json.dumps({
                        'event': EVENT_TIMEOUT
                    }))

                continue

            logging.debug('Received: %s', message_from_io)

            if message_from_io[0] != '*':
                logging.warning('Invalid message from IO board')

                continue

            message_from_io = message_from_io[1:].split('#')

            to_mqtt = self._io_to_mqtt(message_from_io)

            if to_mqtt is None:
                continue

            self._client.publish(*to_mqtt)

    def run(self):
        self._connect_serial()
        self._test_serial()

        self._connect_mqtt()

        self._process_io2mqtt()


def main():
    parser = argparse.ArgumentParser(
        description='Enterprise RFID Unique (EM4100) Access Controller Driver - MQTT<->IOboard link')
    parser.add_argument('--log', default='INFO', choices=('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'),
                        help='log level')
    args = parser.parse_args()

    numeric_level = getattr(logging, args.log.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)
    logging.basicConfig(level=numeric_level)

    config_file = ConfigParser.RawConfigParser()
    config_file.read(['config.ini', 'localconfig.ini'])

    config = EnterpriseDriverConfig(
        serial_url=config_file.get(CONFIG_SECTION_SERIAL, CONFIG_SERIAL_PORT),
        serial_speed=config_file.getint(CONFIG_SECTION_SERIAL, CONFIG_SERIAL_SPEED),
        mqtt_host=config_file.get(CONFIG_SECTION_MQTT, CONFIG_MQTT_HOST),
        mqtt_port=config_file.getint(CONFIG_SECTION_MQTT, CONFIG_MQTT_PORT))

    enterprise_driver = EnterpriseDriver(config=config)
    enterprise_driver.run()


if __name__ == '__main__':
    main()
