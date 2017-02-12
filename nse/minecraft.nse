-- Minecraft Server Probe

description = [[
Checks for Minecraft Servers using the 0x02 "Handshake" protocol
]]

---
-- @output
-- Host script results:
-- |_ minecraft: Minecraft Server!

author = "cbock"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe"}

require "stdnse"
require "shortport"

portrule = shortport.port_or_service(25565, "minecraft")

action = function(host, port)
		
		local socket, result, try, catch, status
		result=""
		status=true
		socket = nmap.new_socket()
		socket:set_timeout(1000)
		catch = function()
        	socket:close()
		end
		
		try=nmap.new_try(catch)
	        try(socket:connect(host, port))
		try(socket:send("\002\000\001\0000"))
		status, result = socket:receive_bytes(16);

		if (not status) then
			socket:close()
			return "Not a Minecraft Server"
		end

		if (result == "TIMEOUT") then
			socket:close()
			return "Not a Minecraft Server"
		end

		socket:close()
		return "Minecraft Server!", result
        
end

