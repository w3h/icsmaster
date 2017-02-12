description = "Fingerprints Red Lion HMI devices"
author = "Thought Leader"
email_address = "thoughtleader@internetofallthethings.com"
license = "TO-ILL"
categories = {"version","discovery"}

stdnse = require "stdnse"

-- Perform discovery using Red Lion Crimson V3 Protocol

-- this method should expose a user configuration
portrule = function(host, port)
	return port.number == 789
end

action = function(host, port) 
	local client = nmap.new_socket()
	local catch = function()
		client:close()
	end

	local try = nmap.new_try(catch)

	-- first fingerprint gets the manufacturer info
	try(client:connect(host.ip, 789))

	local localip, loaclport, remoteip, remoteport = 
		try(client:get_info())
	
	local probe_manufacturer = string.char(0x00,0x04,0x01,0x2b,0x1b,0x00)
	try(client:send(probe_manufacturer))
	resp = try(client:receive())

	if string.len(resp) > 2 then
		-- return the result, skipping the CR3 header and omitting the trailing null
		resp_string = "\nManufacturer: " .. string.sub(resp, 7, -2) 
	end

	try(client:close())

	-- second fingerprint gets the model information
	try(client:connect(host.ip, 789))

	local localip, loaclport, remoteip, remoteport = 
		try(client:get_info())
	
	local probe_manufacturer = string.char(0x00,0x04,0x01,0x2a,0x1a,0x00)
	try(client:send(probe_manufacturer))
	resp = try(client:receive())

	if string.len(resp) > 2 then
		-- return the result, skipping the CR3 header and omitting the trailing null
		resp_string = resp_string .. "\nModel: " .. string.sub(resp, 7, -2) .. "\n"
	end

	try(client:close())

	return resp_string

end
