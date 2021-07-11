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
import random
import string

# Functions
# Generates the ID of the packet
def id_generator(size=5, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

# Button action
def button():
    # Button declaration
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(12, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    
    # Watchdog - Changes to False if the button is pressed. rec() will wait for this
    # to stop and save the .pcap file
    global watchdog
    watchdog = True

    while True:                                                             # Waits the button to be pressed
        time.sleep(0.2)
        input_state = GPIO.input(12)
        if input_state == False:
            watchdog = False
            break

# Mounts USB and sniffs br0 bridge
def rec(block):
    la.lcd_clear()
    la.lcd_display_string("USB Inserted", 1)
    time.sleep(1)
    # Mount USB
    os.system("mount /dev/"+ block +"1 /mnt")                               # Mounts the USB
    la.lcd_clear()                               
    la.lcd_display_string("Sniffing...", 1)
    la.lcd_display_string("Use END to save", 2)
    l = 0                                                                   # Counts the number of packets sniffed
    packetid = id_generator()                                               # Generates the ID of the PCAP file
	
    for plen, t, buf in sniff("br0", out_file="/mnt/puppynose-"+ packetid +".pcap"):  # Here is where the magic happens!
        l = l+1
        if watchdog == False:                                               # If the button is pressed, the watchdog breaks the for() loop
            la.lcd_clear()
            time.sleep(1)
            la.lcd_clear()
            break
    
    la.lcd_clear()
    la.lcd_display_string("Saving...", 1)
    subprocess.run(["umount", "/mnt"])
    la.lcd_clear()
    la.lcd_display_string("Done - ID:" + packetid, 1)
    la.lcd_display_string(str(l) + " Packets", 2)


la = I2C_LCD_driver.lcd()                                                   # Display Declaration

# Welcome message
la.lcd_clear()
la.lcd_display_string("Puppynose v0.1", 1)
la.lcd_display_string(" ", 2)
time.sleep(2)

# Ready message
la.lcd_clear()
la.lcd_display_string("Insert USB to", 1)
la.lcd_display_string("start sniffing!", 2)

# Declaration of pyudev for USB detection
context = pyudev.Context()
monitor = pyudev.Monitor.from_netlink(context)
monitor.filter_by(subsystem='block')
monitor.start()

# Waits for USB insertion
for device in iter(monitor.poll, None):
    time.sleep(0.2)
    if device.sys_path[-3:].isalpha():
        # USB inserted
        if device.action == 'add':
            # If USB is inserted opens a new thread of the rec() function
            t0 = threading.Thread(name='t0', target=rec, args=(device.sys_path[-3:],))
            t0.start()

            # Opens thread for the button() function
            t1 = threading.Thread(name='t1', target=button)
            t1.start()

        # USB removed
        if device.action == 'remove':
            la.lcd_clear()
            la.lcd_display_string("Insert USB to", 1)
            la.lcd_display_string("start sniffing!", 2)