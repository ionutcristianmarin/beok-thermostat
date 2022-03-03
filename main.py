from datetime import datetime
from Crypto.Cipher import AES
from PyCRC.CRC16 import CRC16

import argparse
import pyaes
import time
import random
import socket
import threading


def generate_device(device_type, host, mac):
    devices = {
        hysen: [0x4EAD],  # Hysen controller
    }

    # Look for the class associated to device_type in devices
    [device_class] = [dev for dev in devices if device_type in devices[dev]] or [None]

    if device_class is None:
        return device(host=host, mac=mac, device_type=device_type)
    return device_class(host=host, mac=mac, device_type=device_type)


def discover(timeout=None, local_ip_address=None):
    if local_ip_address is None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 53))  # connecting to a UDP address doesn't send packets
        local_ip_address = s.getsockname()[0]
    address = local_ip_address.split('.')
    cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cs.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    cs.bind((local_ip_address, 0))
    port = cs.getsockname()[1]
    start_time = time.time()

    devices = []

    timezone = int(time.timezone / -3600)
    packet = bytearray(0x30)

    year = datetime.now().year

    if timezone < 0:
        packet[0x08] = 0xff + timezone - 1
        packet[0x09] = 0xff
        packet[0x0a] = 0xff
        packet[0x0b] = 0xff
    else:
        packet[0x08] = timezone
        packet[0x09] = 0
        packet[0x0a] = 0
        packet[0x0b] = 0
    packet[0x0c] = year & 0xff
    packet[0x0d] = year >> 8
    packet[0x0e] = datetime.now().minute
    packet[0x0f] = datetime.now().hour
    sub_year = str(year)[2:]
    packet[0x10] = int(sub_year)
    packet[0x11] = datetime.now().isoweekday()
    packet[0x12] = datetime.now().day
    packet[0x13] = datetime.now().month
    packet[0x18] = int(address[0])
    packet[0x19] = int(address[1])
    packet[0x1a] = int(address[2])
    packet[0x1b] = int(address[3])
    packet[0x1c] = port & 0xff
    packet[0x1d] = port >> 8
    packet[0x26] = 6
    checksum = 0xbeaf

    for i in range(len(packet)):
        checksum += packet[i]
    checksum = checksum & 0xffff
    packet[0x20] = checksum & 0xff
    packet[0x21] = checksum >> 8

    cs.sendto(packet, ('255.255.255.255', 80))
    if timeout is None:
        response = cs.recvfrom(1024)
        response_packet = bytearray(response[0])
        host = response[1]
        mac = response_packet[0x3a:0x40]
        device_type = response_packet[0x34] | response_packet[0x35] << 8

        return generate_device(device_type, host, mac)
    else:
        while (time.time() - start_time) < timeout:
            cs.settimeout(timeout - (time.time() - start_time))
            try:
                response = cs.recvfrom(1024)
            except socket.timeout:
                return devices
            response_packet = bytearray(response[0])
            host = response[1]
            device_type = response_packet[0x34] | response_packet[0x35] << 8
            mac = response_packet[0x3a:0x40]
            dev = generate_device(device_type, host, mac)
            devices.append(dev)
        return devices


class device:
    def __init__(self, host, mac, device_type, timeout=10):
        self.host = host
        self.mac = mac
        self.device_type = device_type
        self.timeout = timeout
        self.count = random.randrange(0xffff)
        self.key = bytearray(
            [0x09, 0x76, 0x28, 0x34, 0x3f, 0xe9, 0x9e, 0x23, 0x76, 0x5c, 0x15, 0x13, 0xac, 0xcf, 0x8b, 0x02])
        self.iv = bytearray(
            [0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58])
        self.id = bytearray([0, 0, 0, 0])
        self.cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.cs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.cs.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.cs.bind(('', 0))
        self.type = "Unknown"
        self.lock = threading.Lock()

        if 'pyaes' in globals():
            self.encrypt = self.encrypt_pyaes
            self.decrypt = self.decrypt_pyaes
        else:
            self.encrypt = self.encrypt_pycrypto
            self.decrypt = self.decrypt_pycrypto

    def encrypt_pyaes(self, payload):
        aes = pyaes.AESModeOfOperationCBC(self.key, iv=bytes(self.iv))
        return b"".join([aes.encrypt(bytes(payload[i:i + 16])) for i in range(0, len(payload), 16)])

    def decrypt_pyaes(self, payload):
        aes = pyaes.AESModeOfOperationCBC(self.key, iv=bytes(self.iv))
        return b"".join([aes.decrypt(bytes(payload[i:i + 16])) for i in range(0, len(payload), 16)])

    def encrypt_pycrypto(self, payload):
        aes = AES.new(bytes(self.key), AES.MODE_CBC, bytes(self.iv))
        return aes.encrypt(bytes(payload))

    def decrypt_pycrypto(self, payload):
        aes = AES.new(bytes(self.key), AES.MODE_CBC, bytes(self.iv))
        return aes.decrypt(bytes(payload))

    def auth(self):
        payload = bytearray(0x50)
        payload[0x04] = 0x31
        payload[0x05] = 0x31
        payload[0x06] = 0x31
        payload[0x07] = 0x31
        payload[0x08] = 0x31
        payload[0x09] = 0x31
        payload[0x0a] = 0x31
        payload[0x0b] = 0x31
        payload[0x0c] = 0x31
        payload[0x0d] = 0x31
        payload[0x0e] = 0x31
        payload[0x0f] = 0x31
        payload[0x10] = 0x31
        payload[0x11] = 0x31
        payload[0x12] = 0x31
        payload[0x1e] = 0x01
        payload[0x2d] = 0x01
        payload[0x30] = ord('T')
        payload[0x31] = ord('e')
        payload[0x32] = ord('s')
        payload[0x33] = ord('t')
        payload[0x34] = ord(' ')
        payload[0x35] = ord(' ')
        payload[0x36] = ord('1')

        response = self.send_packet(0x65, payload)

        payload = self.decrypt(response[0x38:])

        if not payload:
            return False

        key = payload[0x04:0x14]
        if len(key) % 16 != 0:
            return False

        self.id = payload[0x00:0x04]
        self.key = key

        return True

    def get_type(self):
        return self.type

    def send_packet(self, command, payload):
        self.count = (self.count + 1) & 0xffff
        packet = bytearray(0x38)
        packet[0x00] = 0x5a
        packet[0x01] = 0xa5
        packet[0x02] = 0xaa
        packet[0x03] = 0x55
        packet[0x04] = 0x5a
        packet[0x05] = 0xa5
        packet[0x06] = 0xaa
        packet[0x07] = 0x55
        packet[0x24] = 0x2a
        packet[0x25] = 0x27
        packet[0x26] = command
        packet[0x28] = self.count & 0xff
        packet[0x29] = self.count >> 8
        packet[0x2a] = self.mac[0]
        packet[0x2b] = self.mac[1]
        packet[0x2c] = self.mac[2]
        packet[0x2d] = self.mac[3]
        packet[0x2e] = self.mac[4]
        packet[0x2f] = self.mac[5]
        packet[0x30] = self.id[0]
        packet[0x31] = self.id[1]
        packet[0x32] = self.id[2]
        packet[0x33] = self.id[3]

        # pad the payload for AES encryption
        if len(payload) > 0:
            numpad = (len(payload) // 16 + 1) * 16
            payload = payload.ljust(numpad, b"\x00")

        checksum = 0xbeaf
        for i in range(len(payload)):
            checksum += payload[i]
            checksum = checksum & 0xffff

        payload = self.encrypt(payload)

        packet[0x34] = checksum & 0xff
        packet[0x35] = checksum >> 8

        for i in range(len(payload)):
            packet.append(payload[i])

        checksum = 0xbeaf
        for i in range(len(packet)):
            checksum += packet[i]
            checksum = checksum & 0xffff
        packet[0x20] = checksum & 0xff
        packet[0x21] = checksum >> 8

        start_time = time.time()
        with self.lock:
            while True:
                try:
                    self.cs.sendto(packet, self.host)
                    self.cs.settimeout(1)
                    response = self.cs.recvfrom(2048)
                    break
                except socket.timeout:
                    if (time.time() - start_time) > self.timeout:
                        raise
        return bytearray(response[0])


class hysen(device):
    def __init__(self, host, mac, device_type):
        device.__init__(self, host, mac, device_type)
        self.type = "Hysen heating controller"

    # Send a request
    # input_payload should be a bytearray, usually 6 bytes, e.g. bytearray([0x01,0x06,0x00,0x02,0x10,0x00])
    # Returns decrypted payload
    # New behaviour: raises a ValueError if the device response indicates an error or CRC check fails
    # The function prepends length (2 bytes) and appends CRC
    def send_request(self, input_payload):
        crc = CRC16(modbus_flag=True).calculate(bytes(input_payload))

        # first byte is length, +2 for CRC16
        request_payload = bytearray([len(input_payload) + 2, 0x00])
        request_payload.extend(input_payload)

        # append CRC
        request_payload.append(crc & 0xFF)
        request_payload.append((crc >> 8) & 0xFF)

        # send to device
        response = self.send_packet(0x6a, request_payload)

        # check for error
        err = response[0x22] | (response[0x23] << 8)
        if err:
            raise ValueError('broadlink_response_error', err)

        response_payload = bytearray(self.decrypt(bytes(response[0x38:])))

        # experimental check on CRC in response (first 2 bytes are len, and trailing bytes are crc)
        response_payload_len = response_payload[0]
        if response_payload_len + 2 > len(response_payload):
            raise ValueError('hysen_response_error', 'first byte of response is not length')
        crc = CRC16(modbus_flag=True).calculate(bytes(response_payload[2:response_payload_len]))
        if (response_payload[response_payload_len] == crc & 0xFF) and (
                response_payload[response_payload_len + 1] == (crc >> 8) & 0xFF):
            return response_payload[2:response_payload_len]
        else:
            raise ValueError('hysen_response_error', 'CRC check on response failed')

    # Get current room temperature in degrees celsius
    def get_temp(self):
        payload = self.send_request(bytearray([0x01, 0x03, 0x00, 0x00, 0x00, 0x08]))
        return payload[0x05] / 2.0

    # Get current external temperature in degrees celsius
    def get_external_temp(self):
        payload = self.send_request(bytearray([0x01, 0x03, 0x00, 0x00, 0x00, 0x08]))
        return payload[18] / 2.0

    # Get full status (including timer schedule)
    def get_full_status(self):
        payload = self.send_request(bytearray([0x01, 0x03, 0x00, 0x00, 0x00, 0x16]))
        data = {'remote_lock': payload[3] & 1, 'power': payload[4] & 1, 'active': (payload[4] >> 4) & 1,
                'temp_manual': (payload[4] >> 6) & 1, 'room_temp': (payload[5] & 255) / 2.0,
                'thermostat_temp': (payload[6] & 255) / 2.0, 'auto_mode': payload[7] & 15,
                'loop_mode': (payload[7] >> 4) & 15, 'sensor': payload[8], 'osv': payload[9], 'dif': payload[10],
                'svh': payload[11], 'svl': payload[12], 'room_temp_adj': ((payload[13] << 8) + payload[14]) / 2.0}

        if data['room_temp_adj'] > 32767:
            data['room_temp_adj'] = 32767 - data['room_temp_adj']
        data['fre'] = payload[15]
        data['poweron'] = payload[16]
        data['unknown'] = payload[17]
        data['external_temp'] = (payload[18] & 255) / 2.0
        data['hour'] = payload[19]
        data['min'] = payload[20]
        data['sec'] = payload[21]
        data['dayofweek'] = payload[22]

        weekday = []
        for i in range(0, 6):
            weekday.append(
                {'start_hour': payload[2 * i + 23], 'start_minute': payload[2 * i + 24], 'temp': payload[i + 39] / 2.0})

        data['weekday'] = weekday
        weekend = []
        for i in range(6, 8):
            weekend.append(
                {'start_hour': payload[2 * i + 23], 'start_minute': payload[2 * i + 24], 'temp': payload[i + 39] / 2.0})

        data['weekend'] = weekend
        return data

    # Change controller mode auto_mode = 1 for auto (scheduled/timed) mode, 0 for manual mode. Manual mode will
    # activate last used temperature.  In typical usage call set_temp to activate manual control and set temp.
    # loop_mode refers to index in [ "12345,67", "123456,7", "1234567" ] E.g. loop_mode = 0 ("12345,67") means
    # Saturday and Sunday follow the "weekend" schedule loop_mode = 2 ("1234567") means every day (including Saturday
    # and Sunday) follows the "weekday" schedule The sensor command is currently experimental
    def set_mode(self, auto_mode, loop_mode, sensor=0):
        mode_byte = ((loop_mode + 1) << 4) + auto_mode
        # print 'Mode byte: 0x'+ format(mode_byte, '02x')
        self.send_request(bytearray([0x01, 0x06, 0x00, 0x02, mode_byte, sensor]))

    # Advanced settings Sensor mode (SEN) sensor = 0 for internal sensor, 1 for external sensor, 2 for internal
    # control temperature, external limit temperature. Factory default: 0. Set temperature range for external sensor
    # (OSV) osv = 5..99. Factory default: 42C Dead-zone for floor temperature (dIF) dif = 1..9. Factory default: 2C
    # Upper temperature limit for internal sensor (SVH) svh = 5..99. Factory default: 35C Lower temperature limit for
    # internal sensor (SVL) svl = 5..99. Factory default: 5C Actual temperature calibration (AdJ) adj = -0.5.
    # Precision 0.1C Anti-freezing function (FrE) fre = 0 for anti-freezing function shut down, 1 for anti-freezing
    # function open. Factory default: 0 Power on memory (POn) poweron = 0 for power on memory off, 1 for power on
    # memory on. Factory default: 0
    def set_advanced(self, loop_mode, sensor, osv, dif, svh, svl, adj, fre, poweron):
        input_payload = bytearray([0x01, 0x10, 0x00, 0x02, 0x00, 0x05, 0x0a, loop_mode, sensor, osv, dif, svh, svl,
                                   (int(adj * 2) >> 8 & 0xff), (int(adj * 2) & 0xff), fre, poweron])
        self.send_request(input_payload)

    # For backwards compatibility only.  Prefer calling set_mode directly.  Note this function invokes loop_mode=0
    # and sensor=0.
    def switch_to_auto(self):
        self.set_mode(auto_mode=1, loop_mode=0)

    def switch_to_manual(self):
        self.set_mode(auto_mode=0, loop_mode=0)

    # Set temperature for manual mode (also activates manual mode if currently in automatic)
    def set_temp(self, temp):
        self.send_request(bytearray([0x01, 0x06, 0x00, 0x01, 0x00, int(temp * 2)]))

    # Set device on(1) or off(0), does not deactivate Wi-Fi connectivity.  Remote lock disables control by buttons on
    # thermostat.
    def set_power(self, power=1, remote_lock=0):
        self.send_request(bytearray([0x01, 0x06, 0x00, 0x00, remote_lock, power]))

    # set time on device
    # n.b. day=1 is Monday, ..., day=7 is Sunday
    def set_time(self, hour, minute, second, day):
        self.send_request(bytearray([0x01, 0x10, 0x00, 0x08, 0x00, 0x02, 0x04, hour, minute, second, day]))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_help = True
    parser.add_argument('command', help='You can use the following commands: get_full_status, get_room_temp, get_target_temp, set_temp')
    parser.add_argument('-t', '--temperature', help='Thermostat temperature')
    parser.add_argument('params', nargs='*', default=None, type=str)

    args = parser.parse_args()

    command = args.command.lower()
    if command == 'get_full_status':
        thermostat = discover()
        thermostat.auth()
        print(thermostat.get_full_status())
    elif command == 'get_room_temp':
        thermostat = discover()
        thermostat.auth()
        print(thermostat.get_full_status()['room_temp'])
    elif command == 'get_target_temp':
        thermostat = discover()
        thermostat.auth()
        print(thermostat.get_full_status()['thermostat_temp'])
    elif command == 'set_temp':
        if args.temperature is None:
            print('Error: set_temp command requires a temperature param (-t)')
            exit(1)
        thermostat = discover()
        thermostat.auth()
        thermostat.set_temp(float(args.temperature))
    else:
        print('Error: unknown command "%s"' % args.command)
        exit(1)
