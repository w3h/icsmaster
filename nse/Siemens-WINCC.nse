local datafiles = require "datafiles"
local netbios = require "netbios"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Checks for SCADA Siemens <code>WINCC</code> server.

The higher the verbosity or debug level, the more disallowed entries are shown.
]]

---
-- @usage
-- sudo nmap -sU --script Siemens-WINCC.nse -p137 <host>
--
-- @output
-- Host script results:
-- | Siemens-WINCC: 
-- |_  Detected Siemens WINCC_SRV


author = "Jose Ramon Palanco, drainware"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

-- Current version of this script was based entirly on Implementing CIFS, by 
-- Christopher R. Hertel. 
categories = {"default", "discovery", "safe"}


hostrule = function(host)

	-- The following is an attempt to only run this script against hosts
	-- that will probably respond to a UDP 137 probe.  One might argue
	-- that sending a single UDP packet and waiting for a response is no
	-- big deal and that it should be done for every host.  In that case
	-- simply change this rule to always return true.

	local port_t135 = nmap.get_port_state(host,
		{number=135, protocol="tcp"})
	local port_t139 = nmap.get_port_state(host,
		{number=139, protocol="tcp"})
	local port_t445 = nmap.get_port_state(host,
		{number=445, protocol="tcp"})
	local port_u137 = nmap.get_port_state(host,
		{number=137, protocol="udp"})

	return (port_t135 ~= nil and port_t135.state == "open") or
		(port_t139 ~= nil and port_t139.state == "open") or
		(port_t445 ~= nil and port_t445.state == "open") or
		(port_u137 ~= nil and
			(port_u137.state == "open" or
			port_u137.state == "open|filtered"))
end


action = function(host)

	local i
	local status
	local names, statistics
	local server_name
	local mac, prefix, manuf
	local response = {}
	local catch = function() return end
	local try = nmap.new_try(catch)
	

	-- Get the list of NetBIOS names
	status, names, statistics = netbios.do_nbstat(host)
	status, names, statistics = netbios.do_nbstat(host)
	status, names, statistics = netbios.do_nbstat(host)
	status, names, statistics = netbios.do_nbstat(host)
	if(status == false) then
		return stdnse.format_output(false, names)
	end

	-- Get the server name
	status, server_name = netbios.get_server_name(host, names)
	if(status == false) then
		return stdnse.format_output(false, server_name)
	end

	local step1, step2, step3, step4, step5 = nil

	for i = 1, #names, 1 do
		local padding = string.rep(" ", 17 - #names[i]['name'])
		local flags_str = netbios.flags_to_string(names[i]['flags'])
		
		
		
		if string.find(names[i]['name'], "WINCC_SRV") then					
			if names[i]['suffix'] == 0x0 then
				step1 = true
			elseif names[i]['suffix'] == 0x20 then
				step2 = true
			end
		end

		if names[i]['name'] == "SIEMENS" then
			if names[i]['suffix'] == 0x0 then
				step3 = true
			elseif names[i]['suffix'] == 0x1e then
				step4 = true
			elseif names[i]['suffix'] == 0x1d then
				step5 = true
			end			
		end
		
	end

	if step1 and step2 and step3 and step4 and step5 then
		info = string.format("Detected Siemens %s", server_name)
		table.insert(response, info)
	end


	return stdnse.format_output(true, response)


end