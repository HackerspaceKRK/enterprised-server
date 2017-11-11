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

CONFIG_SECTION_SERIAL = 'connection'
CONFIG_SERIAL_PORT = 'serial_port'
CONFIG_SERIAL_SPEED = 'speed'

CONFIG_SECTION_MQTT = 'mqtt'
CONFIG_MQTT_HOST = 'host'
CONFIG_MQTT_PORT = 'port'

EVENT_KEYPRESS = 'keypress'
EVENT_CARDREAD = 'cardread'
EVENT_TAMPER = 'tamper'
EVENT_TIMEOUT = 'timeout'
EVENT_WATCHDOG = 'watchdog'
EVENT_SHUTDOWN = 'shutdown'
EVENT_ACTION = 'action'
