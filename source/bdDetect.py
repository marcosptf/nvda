#bdDetect.py
#A part of NonVisual Desktop Access (NVDA)
#This file is covered by the GNU General Public License.
#See the file COPYING for more details.
#Copyright (C) 2013-2017 NV Access Limited

"""Support for braille display detection.
This allows devices to be automatically detected and used when they become available,
as well as providing utilities to query for possible devices for a particular driver.
To support detection for a driver, devices need to be associated
using the C{add*} functions.
Drivers distributed with NVDA do this at the bottom of this module.
For drivers in add-ons, this must be done in a global plugin.
"""

import itertools
from collections import namedtuple, defaultdict
import threading
import wx
import hwPortUtils
import braille
import winKernel
import core
import ctypes

#: How often (in ms) to poll for Bluetooth devices.
POLL_INTERVAL = 5000

_driverDevices = {}

#: Key for USB HID devices
KEY_USBHID = "usbHid"
#: Key for USB Serial devices
KEY_USBSER = "usbSerial"
#: Key for USB devices with a manufacturer specific driver
KEY_USBCUSTOM = "usbCustom"

#: Key for com ports of an unspecified type, either bluetooth, usb or legacy serial
KEY_COMU = "comUnspecified"
#: Key for Bluetooth com ports
KEY_COMBT = "comBluetooth"

def _getDriver(driver):
	try:
		return _driverDevices[driver]
	except KeyError:
		ret = _driverDevices[driver] = defaultdict(set)
		return ret

def addUsbDevices(driver, type, ids):
	"""Associate USB devices with a driver.
	@param driver: The name of the driver.
	@type driver: str
	@param type: The type of the driver, one of c{KEY_USB*}
	@type type: str
	@param ids: A set of USB IDs in the form C{"VID_xxxx&PID_XXXX"}.
	@type ids: set of str
	"""
	devs = _getDriver(driver)
	driverUsb = devs[type]
	driverUsb.update(ids)

class DeviceMatch(
	namedtuple("DeviceMatch", ("type", "id", "port", "alternateId"))
):
	"""Represents a detected device.
	@ivar type: The type of the device, one of c{KEY_USB*} or c{KEY_COM*}
	@type type: str
	@ivar id: The identifier of the device.
		For C{KEY_USB*}, this is the USB ID
		For C{KEY_COMBT}, this is the Bluetooth name of the device.
		For C{KEY_COMU}, this is the friendly name of the com port.
	@type id: unicode
	@ivar port: The port that can usually be used by a driver to communicate with a device.
		For C{KEY_USBHID} and C{KEY_USBCUSTOM}, this is the device path.
		For C{KEY_USBSER} and C{KEY_COM*}, this is the com port.
	@type port: unicode
	@ivar alternateId: An alternative identifier for the device.
		For C{KEY_USB*} and C{KEY_COMU}, this is the hardware ID.
		For C{KEY_COMBT}, this is the MAC address of the Bluetooth device.
	@type alternateId: unicode
	"""
	__slots__ = ()

def addBluetoothComPorts(driver, matchFunc):
	"""Associate Bluetooth com ports with a driver.
	@param driver: The name of the driver.
	@type driver: str
	@param matchFunc: A function which determines whether a given Bluetooth com port matches.
		It takes a L{BluetoothComPortMatch} as its only argument
		and returns a C{bool} indicating whether it matched.
	@type matchFunc: callable
	"""
	devs = _getDriver(driver)
	devs[KEY_COMBT] = matchFunc

def getDriversForConnectedUsbDevices():
	"""Get any matching drivers for connected USB devices.
	@return: Pairs of drivers and device information.
	@rtype: generator of (str, L{DeviceMatch}) tuples
	"""
	usbDevs = itertools.chain(
		(DeviceMatch(KEY_USBCUSTOM, port["usbID"], port["devicePath"], port["hardwareID"])
		for port in hwPortUtils.listUsbDevices()),
		(DeviceMatch(KEY_USBHID, port["usbID"], port["devicePath"], port["hardwareID"])
		for port in hwPortUtils.listHidDevices() if "usbID" in port),
		(DeviceMatch(KEY_USBSER, port["usbID"], port["port"], port["hardwareID"])
		for port in hwPortUtils.listComPorts() if "usbID" in port)
	)
	for match in usbDevs:
		for driver, devs in _driverDevices.iteritems():
			for type, ids in devs.iteritems():
				if match.type==type and match.id in ids:
					yield driver, match

def getDriversForPossibleBluetoothComPorts():
	"""Get any matching drivers for possible Bluetooth com ports.
	@return: Pairs of drivers and port information.
	@rtype: generator of (str, L{BluetoothComPortMatch}) tuples
	"""
	btComs = [DeviceMatch(KEY_COMBT, port["bluetoothName"], port["port"], port["bluetoothAddress"])
		for port in hwPortUtils.listComPorts()
		if "bluetoothName" in port]
	for driver, devs in _driverDevices.iteritems():
		matchFunc = devs[KEY_COMBT]
		if not callable(matchFunc):
			continue
		for port in btComs:
			if matchFunc(port):
				yield driver, port

class Detector(object):
	"""Automatically detect braille displays.
	This should only be used by the L{braille} module.
	"""

	def __init__(self):
		self._BgScanApc = winKernel.PAPCFUNC(self._bgScan)
		self._btComs = None
		self._pollTimer = winKernel.createWaitableTimer()
		self._detectUsb = False
		self._detectBluetooth = False
		core.hardwareChanged.register(self.rescan)
		# Perform initial scan.
		self._startBgScan(usb=True, bluetooth=True)

	def _startBgScan(self, usb=False, bluetooth=False, callAfter=0):
		self._stopEvent = threading.Event()
		self._detectUsb = usb
		self._detectBluetooth = bluetooth
		if callAfter:
			winKernel.setWaitableTimer(
				self._pollTimer,
				POLL_INTERVAL,
				0,
				self._BgScanApc
			)
		else:
			braille._BgThread.queueApc(self._BgScanApc)

	def _stopBgScan(self):
		self._stopEvent.set()
		if self._pollTimer:
			if not winKernel.kernel32.CancelWaitableTimer(self._pollTimer):
				raise ctypes.WinError()

	def _bgScan(self, param):
		# Cache variables 
		stopEvent = self._stopEvent
		usb = self._detectUsb
		bluetooth = self._detectBluetooth
		if usb:
			if stopEvent.isSet():
				return
			for driver, match in getDriversForConnectedUsbDevices():
				if braille.handler.setDisplayByName(driver, detected=match):
					return

		if bluetooth:
			if self._btComs is None:
				btComs = list(getDriversForPossibleBluetoothComPorts())
				# Cache Bluetooth com ports for next time.
				btComsCache = []
			else:
				btComs = self._btComs
				btComsCache = btComs
			for driver, match in btComs:
				if btComsCache is not btComs:
					btComsCache.append((driver, match))
				if stopEvent.isSet():
					return
				if braille.handler.setDisplayByName(driver, detected=match):
					break
			if stopEvent.isSet():
				return
			if btComsCache is not btComs:
				self._btComs = btComsCache
			if btComsCache:
				# There were possible ports, so poll them periodically.
				self._startBgScan(bluetooth=True, callAfter=POLL_INTERVAL)

	def rescan(self):
		"""Stop a current scan when in progress, and start scanning from scratch"""
		self._stopBgScan()
		# A Bluetooth com port might have been added.
		self._btComs = None
		self._startBgScan(usb=True, bluetooth=True)

	def terminate(self):
		core.hardwareChanged.unregister(self.rescan)
		self._stopBgScan()
		winKernel.closeHandle(self._pollTimer)

def getConnectedUsbDevicesForDriver(driver):
	"""Get any connected USB devices associated with a particular driver.
	@param driver: The name of the driver.
	@type driver: str
	@return: Device information for each device.
	@rtype: generator of L{DeviceMatch}
	@raise LookupError: If there is no detection data for this driver.
	"""
	devs = _driverDevices[driver]
	usbDevs = itertools.chain(
		(DeviceMatch(KEY_USBCUSTOM, port["usbID"], port["devicePath"], port["hardwareID"])
		for port in hwPortUtils.listUsbDevices()),
		(DeviceMatch(KEY_USBHID, port["usbID"], port["devicePath"], port["hardwareID"])
		for port in hwPortUtils.listHidDevices() if "usbID" in port),
		(DeviceMatch(KEY_USBSER, port["usbID"], port["port"], port["hardwareID"])
		for port in hwPortUtils.listComPorts() if "usbID" in port)
	)
	for match in usbDevs:
		for type, ids in devs.iteritems():
			if match.type==type and match.id in ids:
				yield driver, match

def getPossibleBluetoothComPortsForDriver(driver):
	"""Get any possible Bluetooth com ports associated with a particular driver.
	@param driver: The name of the driver.
	@type driver: str
	@return: Port information for each port.
	@rtype: generator of L{BluetoothComPortMatch}
	@raise LookupError: If there is no detection data for this driver.
	"""
	matchFunc = _driverDevices[driver][KEY_COMBT]
	if not callable(matchFunc):
		return
	for port in hwPortUtils.listComPorts():
		if not "bluetoothName" in port:
			continue
		match = DeviceMatch(KEY_COMBT, port["bluetoothName"], port["port"], port["bluetoothAddress"])
		if matchFunc(match):
			yield match

def arePossibleDevicesForDriver(driver):
	"""Determine whether there are any possible devices associated with a given driver.
	@param driver: The name of the driver.
	@type driver: str
	@return: C{True} if there are possible devices, C{False} otherwise.
	@rtype: bool
	@raise LookupError: If there is no detection data for this driver.
	"""
	return bool(next(itertools.chain(
		getConnectedUsbDevicesForDriver(driver),
		getPossibleBluetoothComPortsForDriver(driver)
	), None))

### Detection data
# baum
addUsbDevices("baum", KEY_USBHID, {
	"VID_0904&PID_3001", # RefreshaBraille 18
	"VID_0904&PID_6101", # VarioUltra 20
	"VID_0904&PID_6103", # VarioUltra 32
	"VID_0904&PID_6102", # VarioUltra 40
	"VID_0904&PID_4004", # Pronto! 18 V3
	"VID_0904&PID_4005", # Pronto! 40 V3
	"VID_0904&PID_4007", # Pronto! 18 V4
	"VID_0904&PID_4008", # Pronto! 40 V4
	"VID_0904&PID_6001", # SuperVario2 40
	"VID_0904&PID_6002", # SuperVario2 24
	"VID_0904&PID_6003", # SuperVario2 32
	"VID_0904&PID_6004", # SuperVario2 64
	"VID_0904&PID_6005", # SuperVario2 80
	"VID_0904&PID_6006", # Brailliant2 40
	"VID_0904&PID_6007", # Brailliant2 24
	"VID_0904&PID_6008", # Brailliant2 32
	"VID_0904&PID_6009", # Brailliant2 64
	"VID_0904&PID_600A", # Brailliant2 80
	"VID_0904&PID_6201", # Vario 340
	"VID_0483&PID_A1D3", # Orbit Reader 20
})

addUsbDevices("baum", KEY_USBSER, {
	"VID_0403&PID_FE70", # Vario 40
	"VID_0403&PID_FE71", # PocketVario
	"VID_0403&PID_FE72", # SuperVario/Brailliant 40
	"VID_0403&PID_FE73", # SuperVario/Brailliant 32
	"VID_0403&PID_FE74", # SuperVario/Brailliant 64
	"VID_0403&PID_FE75", # SuperVario/Brailliant 80
	"VID_0904&PID_2001", # EcoVario 24
	"VID_0904&PID_2002", # EcoVario 40
	"VID_0904&PID_2007", # VarioConnect/BrailleConnect 40
	"VID_0904&PID_2008", # VarioConnect/BrailleConnect 32
	"VID_0904&PID_2009", # VarioConnect/BrailleConnect 24
	"VID_0904&PID_2010", # VarioConnect/BrailleConnect 64
	"VID_0904&PID_2011", # VarioConnect/BrailleConnect 80
	"VID_0904&PID_2014", # EcoVario 32
	"VID_0904&PID_2015", # EcoVario 64
	"VID_0904&PID_2016", # EcoVario 80
	"VID_0904&PID_3000", # RefreshaBraille 18
})

addBluetoothComPorts("baum", lambda m: any(m.id.startswith(prefix) for prefix in (
	"Baum SuperVario",
	"Baum PocketVario",
	"Baum SVario",
	"HWG Brailliant",
	"Refreshabraille",
	"VarioConnect",
	"BrailleConnect",
	"Pronto!",
	"VarioUltra",
	"Orbit Reader 20",
)))

# brailleNote
addUsbDevices("brailleNote", KEY_USBSER, {
	"VID_1C71&PID_C004", # Apex
})
addBluetoothComPorts("brailleNote", lambda m:
	any(first <= m.alternateId <= last for first, last in (
		(0x0025EC000000, 0x0025EC01869F), # Apex
	)) or m.id.startswith("Braillenote"))

# brailliantB
addUsbDevices("brailliantB", KEY_USBHID, {"VID_1C71&PID_C006"})
addUsbDevices("brailliantB", KEY_USBCUSTOM, {"VID_1C71&PID_C005"})
addBluetoothComPorts("brailliantB", lambda m:
	m.id.startswith("Brailliant B") or m.id == "Brailliant 80")

# handyTech
addUsbDevices("handyTech", KEY_USBSER, {
	"VID_0403&PID_6001", # FTDI chip
	"VID_0921&PID_1200", # GoHubs chip
})

# Newer Handy Tech displays have a native HID processor
addUsbDevices("handyTech", KEY_USBHID, {
	"VID_1FE4&PID_0054", # Active Braille
	"VID_1FE4&PID_0081", # Basic Braille 16
	"VID_1FE4&PID_0082", # Basic Braille 20
	"VID_1FE4&PID_0083", # Basic Braille 32
	"VID_1FE4&PID_0084", # Basic Braille 40
	"VID_1FE4&PID_008A", # Basic Braille 48
	"VID_1FE4&PID_0086", # Basic Braille 64
	"VID_1FE4&PID_0087", # Basic Braille 80
	"VID_1FE4&PID_008B", # Basic Braille 160
	"VID_1FE4&PID_0061", # Actilino
	"VID_1FE4&PID_0064", # Active Star 40
})

# Some older HT displays use a HID converter and an internal serial interface
addUsbDevices("handyTech", KEY_USBHID, {
	"VID_1FE4&PID_0003", # USB-HID adapter
	"VID_1FE4&PID_0074", # Braille Star 40
	"VID_1FE4&PID_0044", # Easy Braille
})

addBluetoothComPorts("handyTech", lambda m: any(m.id.startswith(prefix) for prefix in (
	"Actilino AL",
	"Active Braille AB",
	"Active Star AS",
	"Basic Braille BB",
	"Braille Star BS",
	"Braille Wave BW",
	"Easy Braille EBR",
)))

# superBrl
addUsbDevices("superBrl", KEY_USBSER, {
	"VID_10C4&PID_EA60", # SuperBraille 3.2
})
