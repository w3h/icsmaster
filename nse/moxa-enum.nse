-- Nmap Scripting Engine
-- required packages for this script
--
-- ICS Discovery Tools Releases
-- ICS Security Workspace
---
-- usage:
-- nmap -sU --script moxa-enum -p 4800 <ip>
--
-- Output:
--  PORT      STATE SERVICE REASON
--  4800/tcp open|filtered  iims    no-response
--  | moxa-enum:
--  |   Moxa Nport Devices Status: Fixed --Password setting status
--  |	Server Name: NP5110_2439 --Target device information
--  |_ 
local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
用于识别Moxa Nport系列串口服务器设备,并且识别设备的型号和密码设置状态.
enumerate Moxa Nport devices,and read the target device information,Password setting status

]]
author = "Z-0ne(plcscan.org)"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","intrusive"}

portrule = shortport.port_or_service(4800, "moxaudp", "udp")
action = function(host, port)
	local output = stdnse.output_table()
	local response, status
	local session1 = bin.pack("H", "0100000800000000")
	local socket = nmap.new_socket()
	socket:set_timeout(13000)
	try = nmap.new_try(function() socket:close() end)
	try(socket:connect(host, port))
	try(socket:send(session1))
	local status, response = socket:receive()
	if ( status and #response > 0 ) then
		local pos, protocolid1, protocolid2 = bin.unpack("CC", response, 1, 2)
		if ( protocolid1 == 0x81 and protocolid2 == 0x00 ) then
			local recvpacket = string.sub(response, 5, 20)
			local secondpack = bin.pack("H", "16000014")..recvpacket
			local thirdpack = bin.pack("H", "10000014")..recvpacket
			try(socket:send(secondpack))
			local status, response = socket:receive()
			if ( status and #response > 0 ) then
				local pos, protocolid1 = bin.unpack("C", response, 1)
				if ( status and protocolid1 == 0x96 ) then
					try(socket:send(thirdpack))
					local status, response = socket:receive()
					if ( status and #response > 21 ) then
						local pos, devicestatuscode = bin.unpack("C", response, 33) --Status Code: 0x01 Lock Fixed (Have Password)/0x00 Fixed(Not Have Password)
						local pos, servername = bin.unpack("z", response, 21)
						if ( devicestatuscode == 0x00 ) then
							output["Moxa Nport Devices Status"] = "Fixed"
							output["Server Name"] = servername
							socket:close()
							return output
						elseif ( devicestatuscode == 0x01 ) then
							output["Moxa Nport Devices Status"] = "Lock Fixed"
							output["Server Name"] = servername
							socket:close()
							return output
						else
							output["Devices"] = "Moxa Devices"
							output["Server Name"] = servername
							socket:close()
							return output
						end
					elseif ( status and #response <= 21 ) then
						output["Devices"] = "Moxa Devices"
						output["Response(HEX)"] = stdnse.tohex(response)
						socket:close()
						return output
					end
					socket:close()
				elseif ( status and protocolid1 ~= 0x96 ) then
					output["Devices"] = "Moxa Devices"
					output["Response(HEX)"] = stdnse.tohex(response)
					socket:close()
					return output
				end
			end
			socket:close()
		end
	end
	socket:close()
end
					
				
			













