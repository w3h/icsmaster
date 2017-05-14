description = [[
    Attemts to find valid sid for tcp modbus server.
]]

---
-- @usage
-- nmap --script modbus-enum.nse --script-args='functionId=8, aggressive=true, data="00 AA BB CC"' -p 502 <host>
--
-- @args functionId - modbus request function id. Valid function codes are 1-247
-- @args aggressive - boolean value defines find all or just first sid
-- @args data - payload data for modbus request in hex form. Example: "AA BB CC DD"
-- 
-- @output
-- PORT    STATE SERVICE
-- 502/tcp open  modbus
-- | modbus-enum:
-- |   Positive response for sid = 0x64
-- |   Positive error response for sid = 0x96
-- |_  Positive response for sid = 0xc8
--
-- Version 0.1
--
-- This script is a NSE port of modscan utility written by Mark Bristow.
-- MODBUS TCP protocol has no any authentication and allow to find information
-- about legal sids by bruteforse.
-- Presentation about tcp modbus protocol and modscan utility from Defcon 16
-- can be found here https://www.defcon.org/images/defcon-16/dc16-presentations/defcon-16-bristow.pdf
-- Modscan utility is hosted at google code: http://code.google.com/p/modscan/
--
---

author = "Alexander Rudakov"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

require "bin"
require "comm"
require "stdnse"
require "shortport"

portrule = shortport.portnumber(502, "tcp")

local form_rsid = function(sid, functionId, data)
	local payload_len = 2
	if  ( #data > 0 ) then
	    payload_len = payload_len + #data
	end
	return bin.pack('CCCCC', 0x00, 0x00, 0x00, 0x00, 0x00) .. bin.pack('C', payload_len) .. bin.pack('C', sid) .. bin.pack('C', functionId) .. data
end

action = function(host, port)
	local functionId = 8 -- default function code for diagnostics
	local aggressive = false -- stop on first founded sid
	local data = "00 00 AA BB" -- diagnostic code, just return data
	
	if (nmap.registry.args['functionId']) then
	    functionId = nmap.registry.args['functionId']
	end
	
	if (nmap.registry.args['aggressive']) then
	    aggressive = nmap.registry.args['aggressive']
	end
	
	if (nmap.registry.args['data']) then
	    data = bin.pack('H', nmap.registry.args['data'])
	end
	
	
	local results = {}
	for sid = 1, 246 do
		stdnse.print_debug(3, "Sending command with sid = %d", sid)
		rsid = form_rsid(sid, functionId, data)
		
		local status, result = comm.exchange(host, port, rsid)
		if ( status and #result >= 8 ) then
			local ret_code = string.byte(result, 8)
			if ret_code == (functionId + 0) then
		    		table.insert(results, ("Positive response for sid = 0x%x"):format(sid))
		    		if ( not aggressive ) then break end
			elseif ret_code == (functionId + 128) then
		    		table.insert(results, ("Positive error response for sid = 0x%x"):format(sid))
		    		if ( not aggressive ) then break end
			end
		end	
	end
	if ( #results > 0 ) then
	    port.state = "open"
	    port.version.name = "modbus"
	    nmap.set_port_version(host, port, "hardmatched")
	end
	
	return stdnse.format_output(true, results)
end
