# icsmaster

整合工控安全相关资源


# 目录说明

doc -------------- 收集Paper

exploit ---------- 收集利用脚本

firmware --------- 收集固件

nse -------------- 收集Nmap脚本

pcap ------------- 收集工控协议数据包

protocol --------- 收集工控协议库

tool ------------- 收集相关工具


# Paper

* [BlackHat 2011 - Exploiting Siemens Simatic S7 PLCs](https://github.com/w3h/icsmaster/blob/master/doc/%E5%9B%BD%E5%A4%96/Exploiting%20Siemens%20Simatic%20S7%20PLCs.pdf)
* [BlackHat 2015 - Internet-facing PLCs – A New Back Orifice](https://github.com/w3h/icsmaster/blob/master/doc/%E5%9B%BD%E5%A4%96/us-15-Klick-Internet-Facing-PLCs-A-New-Back-Orifice-wp.pdf)
* [BlackHat 2016 - PLC-Blaster: A Worm Living Solely in the PLC](https://github.com/w3h/icsmaster/blob/master/doc/%E5%9B%BD%E5%A4%96/asia-16-Spenneberg-PLC-Blaster-A-Worm-Living-Solely-In-The-PLC-wp.pdf)
* [工业控制系统梯形图逻辑炸弹](https://github.com/w3h/icsmaster/blob/master/doc/%E5%9B%BD%E5%A4%96/On%20Ladder%20Logic%20Bombs%20in%20Industrial%20Control%20Systems.pdf)
* [失控：工业控制系统勒索软件](https://github.com/w3h/icsmaster/blob/master/doc/%E5%9B%BD%E5%A4%96/plcransomware.pdf)
* [黑客如何入侵今日智慧工厂工业机器人](https://github.com/w3h/icsmaster/blob/master/doc/%E5%9B%BD%E5%A4%96/wp-industrial-robot-security.pdf)
* [著名工控安全组织（SCADA StrangeLove）相关Paper](https://github.com/w3h/icsmaster/tree/master/doc/%E5%9B%BD%E5%A4%96/SCADA%20StrangeLove)

[...](https://github.com/w3h/icsmaster/tree/master/doc)

# NSE脚本

* [BACnet-discover-enumerate.nse](https://github.com/w3h/icsmaster/blob/master/nse/BACnet-discover-enumerate.nse) - Identify and enumerate BACnet devices
* [enip-enumerate.nse](https://github.com/w3h/icsmaster/blob/master/nse/enip-enumerate.nse) - Identify and enumerate EtherNet/IP devices from Rockwell Automation and other vendors
* [fox-info.nse](https://github.com/w3h/icsmaster/blob/master/nse/fox-info.nse) - Identify and enumerate Niagara Fox devices
* [modicon-info.nse](https://github.com/w3h/icsmaster/blob/master/nse/modicon-info.nse) - Identify and enumerate Schneider Electric Modicon PLCs
* [omron-info.nse](https://github.com/w3h/icsmaster/blob/master/nse/omron-info.nse) - Identify and enumerate Omron PLCs
* [pcworx-info.nse](https://github.com/w3h/icsmaster/blob/master/nse/pcworx-info.nse) - Identify and enumerate PC Worx Protocol enabled PLCs
* [proconos-info.nse](https://github.com/w3h/icsmaster/blob/master/nse/pcworx-info.nse) - Identify and enumerate ProConOS enabled PLCs
* [s7-enumerate.nse](https://github.com/w3h/icsmaster/blob/master/nse/s7-enumerate.nse) - Identify and enumerate Siemens SIMATIC S7 PLC

[...](https://github.com/w3h/icsmaster/tree/master/nse)

# 工具

* [ModbusDroid](https://github.com/w3h/icsmaster/blob/master/tool/ModbusDroid.apk) - 安卓版Modbus协议工具
* [s7clientdemo](https://github.com/w3h/icsmaster/blob/master/tool/s7clientdemo.rar) - 支持西门子S7-300和S7-400控制器操作的工具
* [SCADAShutdownTool](https://github.com/w3h/icsmaster/blob/master/tool/SCADAShutdownTool-v1.0-Beta.zip) - 关闭Scada系统

[...](https://github.com/w3h/icsmaster/tree/master/tool)

# 协议库

* CIP
* s7

[...](https://github.com/w3h/icsmaster/tree/master/protocol)

# 数据包

* [bacnet](https://github.com/w3h/icsmaster/tree/master/pcap/bacnet)
* [dnp3](https://github.com/w3h/icsmaster/tree/master/pcap/dpn3)
* [enip](https://github.com/w3h/icsmaster/tree/master/pcap/enip)
* [fox](https://github.com/w3h/icsmaster/tree/master/pcap/fox)
* [modbus](https://github.com/w3h/icsmaster/tree/master/pcap/modbus)
* [modicon](https://github.com/w3h/icsmaster/tree/master/pcap/modicon)
* [omron](https://github.com/w3h/icsmaster/tree/master/pcap/omron)
* [opc](https://github.com/w3h/icsmaster/tree/master/pcap/opc)
* [s7](https://github.com/w3h/icsmaster/tree/master/pcap/s7)

[...](https://github.com/w3h/icsmaster/tree/master/pcap)





