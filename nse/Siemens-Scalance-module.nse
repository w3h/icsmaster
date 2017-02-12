local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Checks for SCADA Siemens <code>SCALANCE</code> modules.

The higher the verbosity or debug level, the more disallowed entries are shown.
]]

---
-- @output
-- | Siemens-Scalance-module:  
-- |_  SCALANCE W788-1PRO


author = "Jose Ramon Palanco, drainware"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
dependencies = {"snmp-brute"}


portrule = shortport.portnumber(161, "udp", {"open", "open|filtered"})


function process_answer( tbl )

	local new_tab = {}

	for _, v in ipairs( tbl ) do
		if string.find (v.value, "SCALANCE")  then
			version = v.value:gsub("SCALANCE", "VERSION:")
			model = version:match("%W+ %s*(.-)%d%d%d")
			if model == "W" then
			  version = version .. " (wireless device)" 
			elseif model == "X" then
			  version = version .. " (network switch)" 
			elseif model == "S" then
			  version = version .. " (firewall)" 			
			end			
		else
			return nil
		end
		table.insert( new_tab, version)
	end
	
	table.sort( new_tab )
	
	return new_tab
	
end

action = function(host, port)

	local socket = nmap.new_socket()
	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)	
	local snmpoid = "1.3.6.1.2.1.1.1"	
	local services = {}
	local status

	socket:set_timeout(5000)
	try(socket:connect(host, port))
	
	status, services = snmp.snmpWalk( socket, snmpoid )
	socket:close()


	if ( not(status) ) or ( services == nil ) or ( #services == 0 ) then
		return
	end
	
	services = process_answer(services)

	if services == nil then 
		return
	end	
	
	nmap.set_port_state(host, port, "open")

	return stdnse.format_output( true, services )
end
