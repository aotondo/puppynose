import pyudev
import threading
import os
import subprocess
import time
from subprocess import Popen, PIPE
from os import system, name
import smbus
import time
import RPi.GPIO as GPIO
import I2C_LCD_driver
from pylibpcap.pcap import sniff

# Functions
# Button action
def button():
    # Button declaration
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(12, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    
    # Watchdog - Changes to False if the button is pressed. rec() will wait for this
    # to stop and save the .pcap file
    global watchdog
    watchdog = True

    while True:
        time.sleep(0.2)
        input_state = GPIO.input(12)
        if input_state == False:
            print("BUTTON pressed")
            watchdog = False
            la.lcd_display_string("BUTTON", 1)
            break

# Mounts USB and sniffs br0 bridge
def rec(block):
    la.lcd_clear()
    la.lcd_display_string("USB Inserted!", 1)
    time.sleep(1)
    
    # Mount USB
    os.system("mount /dev/"+ block +"1 /mnt")
    la.lcd_display_string("USB Inserted!", 1)
    for plen, t, buf in sniff("br0", out_file="pcap.pcap"):
        if watchdog == False:   # If the button is pressed, the watchdog makes break the for loop 
            break

# Display Declaration
la = I2C_LCD_driver.lcd()

# Welcome message
la.lcd_clear()
la.lcd_display_string("Puppynose v0.1", 1)
la.lcd_display_string(" ", 2)
time.sleep(2)

# Ready message
la.lcd_clear()
la.lcd_display_string("Insert USB and", 1)
la.lcd_display_string("press REC", 2)

# Declaration of pyudev for USB detection
context = pyudev.Context()
monitor = pyudev.Monitor.from_netlink(context)
monitor.filter_by(subsystem='block')
monitor.start()

# Waits for USB insertion
for device in iter(monitor.poll, None):
    if device.sys_path[-3:].isalpha():
        if device.action == 'add':
            # If USB is inserted opens a new thread of the rec() function
            t0 = threading.Thread(name='t0', target=rec, args=(device.sys_path[-3:],))
            t0.start()

            # Opens thread for the button() function
            t1 = threading.Thread(name='t1', target=button)
            t1.start()
            break
            