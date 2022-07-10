import serial
import serial.tools.list_ports
import re
from datetime import datetime
datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')

logfile = open("./log/"+ datetime.now().strftime('%Y-%m-%d %H:%M:%S') +".log", 'w', buffering=1)
csvfile = open("./data/"+ datetime.now().strftime('%Y-%m-%d %H:%M:%S') +".csv", 'w', buffering=1)
csvfile.write("device,time,OpCode\n")
csvfile.flush()

class UARTdevice:
    def __init__(self, dev, num):
        self.dev = serial.Serial(dev, 115200)
        self.number = num
        self.data = ""
        self.debuglog = []
        self.infolog = []
        self.debugLog_regex = re.compile(r'^D: ')
        self.infoLog_regex = re.compile(r'^I: ')
        self.OP_regex = re.compile(r'^OP: ')
        self.device_regex = re.compile(r'^DEV: ')
    
    def debuglog_passer(self, data):
        if(self.debugLog_regex.search(data)): 
            result = re.sub(self.debugLog_regex, '', data)
            self.debuglog.append(result)
            print(datetime.now().strftime('[%Y-%m-%d %H:%M:%S.%f]'),\
                    self.number, len(self.debuglog), result, end="")
    
    def infobuglog_passer(self, data):
        global logfile
        if(self.infoLog_regex.search(data)): 
            result = re.sub(self.infoLog_regex, '', data)
            
            # Devices INFO_LOG
            if(self.device_regex.search(result)): 
                self.number = re.sub(self.device_regex, '', result).strip()
                return 

            # OP INFO_LOG
            if(self.OP_regex.search(result)): 
                self.infolog.append(result)
                date_T = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
                outlog = "[" + date_T + "] " + str(self.number) + " " + str(len(self.infolog)) + " " + result
                csvlog = str(self.number) + "," + date_T + "," + re.sub(self.OP_regex, '', result)
                print(outlog, end="")
                logfile.write(outlog)
                logfile.flush()
                csvfile.write(csvlog)
                csvfile.flush()
                return 


devices = []
port_list = sorted(serial.tools.list_ports.comports())
index=0
# for index in range(len(port_list)):
#     devices.append(UARTdevice(port_list[index].device, index))

for device in port_list:
    port, desc, hwid = device
    print("{}: {} [{}]".format(port, desc, hwid))
    if(desc == "J-Link - CDC"):
        print("GET DEVICE")
        devices.append(UARTdevice(device.device, index))
        index+=1
print(devices)

while True:
    for device in devices:
        data = device.dev.readline()
        if data:
            # print(data)
            # device.debuglog_passer(data.decode())
            device.infobuglog_passer(data.decode())
        # try:
        #     data = device.dev.readline()
        #     if data:
        #         # print(data)
        #         # device.debuglog_passer(data.decode())
        #         device.infobuglog_passer(data.decode())
        # except:
        #     devices.remove(device)
            