-- Nmap Scripting Engine
-- required packages for this script
--
-- ICS Discovery Tools Releases
-- ICS Security Workspace(plcscan.org)
---

local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"


description = [[
discover Siemens SIMATIC S7 1200 PLC.
Based on TIA Portal software.

]]

author = "ICS Security Workspace(plcscan.org)"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","intrusive"}

--
-- @usage
-- nmap -sP --script s71200-enumerate-old.nse -p 102 <host/s>
--
-- @output
--102/tcp open  Siemens S7 1200 Ethernet Controller
--| s71200-enumerate-old.nse:
--|   Basic Hardware: 6ES7 212-1HE31-0XB0
--|_  Firmware Version: V3.0
--

function set_nmap(host, port)
	port.state = "open"
	port.version.name = "iso-tsap"
	port.version.product = "Siemens S7 1200 Ethernet Controller"
	nmap.set_port_version(host, port)
	nmap.set_port_state(host, port, "open")

end

function send_receive(socket, query)
	local sendstatus, senderr = socket:send(query)
	if(sendstatus == false) then
	return "Error Sending pack"
	end
	local rcvstatus,response = socket:receive()
	if(rcvstatus == false) then
	return "Error Reading pack"
	end
	return response
	end

portrule = shortport.port_or_service(102, "iso-tsap", "tcp")
action = function(host,port)
--  soft handshake Methods one
	local connectpack = bin.pack("H","030000231ee00000000600c1020600c20f53494d415449432d524f4f542d4553c0010a")
--  soft handshake Methods two
--	local connectpack = bin.pack("H","0300001611e00000000800c1020600c2020600c0010a")
-- send local connection packet(IE NIC and session)
	local gethwinfo = bin.pack("H","030000e502f080720100d631000004ca00000001"..
									"00000120360000011d00040000000000a1000000"..
									"d3821f0000a38169001515536572766572536573"..
									"73696f6e5f31433943333932a3822100152c313a"..
									"3a3a362e303a3a5443502f4950202d3e2042726f"..
									"6164636f6d204e65744c696e6b2028544d29202e"..
									"2e2ea38228001500a38229001500a3822a001516"..
									"4846504654385246375052474837595f34313831"..
									"3731a3822b000401a3822c001201c9c392a3822d"..
									"001500a1000000d3817f0000a381690015155375"..
									"62736372697074696f6e436f6e7461696e6572a2"..
									"a20000000072010000")	
	local response
	local output = stdnse.output_table()
	local sock = nmap.new_socket()
	local constatus,conerr = sock:connect(host,port)
	if not constatus then
	stdnse.print_debug(1,
      'Error establishing connection for %s - %s', host,conerr
      )
	return nil
	end
	response  = send_receive(sock, connectpack)
	local s7, length_hex = bin.unpack("C", response, 4)
	if ( length_hex == 0x23 ) then
		s7, output["Connectstatus"] = "S7 Connect ok"
		response  = send_receive(sock, gethwinfo)
		local s7, protocol_id = bin.unpack("C", response, 1)
		if ( #response > 80 and protocol_id == 0x03 ) then
			local s, e = string.find(response, "6ES7")
			local o, d = string.find(response, "V")
			local offset = 15
			output["Basic Hardware"] = string.sub(response, s, e + offset)
			output["Firmware Version"] = string.sub(response, o, d + 3)
			set_nmap(host, port)
			sock:close()
			return output
		end
		sock:close()
	end		
end