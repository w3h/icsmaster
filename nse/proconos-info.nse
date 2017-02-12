local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
This NSE script will query and parse ProConOs protocol to a remote PLC. 
The script will send a initial request packet and once a
response is received, it validates that it was a proper response to the command
that was sent, and then will parse out the data. 

http://digitalbond.com

]]
---
-- @usage
-- nmap --script proconos-info -p 20547 <host>
--
--
-- @output
--| proconos-info: 
--|   Ladder Logic Runtime: ProConOS V3.0.1040 Oct 29 2002
--|   PLC Type: ADAM5510KW 1.24 Build 005
--|   Project Name: 510-projec
--|   Boot Project: 510-projec
--|_  Project Source Code: Exist 
--
--
-- @xmloutput
--<elem key="Ladder Logic Runtime">ProConOS V3.0.1040 Oct 29 2002</elem>
--<elem key="PLC Type">ADAM5510KW 1.24 Build 005</elem>
--<elem key="Project Name">510-projec</elem>
--<elem key="Boot Project">510-project</elem>
--<elem key="Project Source Code">Exist</elem>
author = "Stephen Hilt (Digital Bond)"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "version"}

--
-- Function to define the portrule as per nmap standards
--
--
portrule = shortport.portnumber(20547, "tcp")

---
--  Function to set the nmap output for the host, if a valid PCPROTOCOL packet
--  is received then the output will show that the port is open instead of
--  <code>open|filtered</code>
--
-- @param host Host that was passed in via nmap
-- @param port port that PCPROTOCOL is running on (Default TCP/1962)
function set_nmap(host, port)

  --set port Open
  port.state = "open"
  -- set version name to PCPROTOCOL
  port.version.name = "ProConOS"
  nmap.set_port_version(host, port)
  nmap.set_port_state(host, port, "open")

end

---
--  Action Function that is used to run the NSE. This function will send the initial query to the
--  host and port that were passed in via nmap. The initial response is parsed to determine if host
--  is a PCPROTOCOL device. If it is then more actions are taken to gather extra information.
--
-- @param host Host that was scanned via nmap
-- @param port port that was scanned via nmap
action = function(host,port)
  local req_info = bin.pack("H","cc01000b4002000047ee")
  -- create table for output
  local output = stdnse.output_table()
  -- create local vars for socket handling
  local socket, try, catch
  -- create new socket
  socket = nmap.new_socket()
  -- define the catch of the try statement
  catch = function()
    socket:close()
  end
  -- create new try
  try = nmap.new_try(catch)
  try(socket:connect(host, port))
  -- connect to port on host
  try(socket:send(req_info))
  -- receive response
  local rcvstatus, response = socket:receive()
  if(rcvstatus == false) then
    return false, response
  end    local pos, check1 = bin.unpack("C",response,1)
  -- if the fist byte is 0xcc 
  if(check1 == 0xcc) then
	set_nmap(host, port)
    -- create output table with proper data
    pos, output["Ladder Logic Runtime"] = bin.unpack("z",response,13)
	pos, output["PLC Type"] = bin.unpack("z",response, 45)
	pos, output["Project Name"] = bin.unpack("z", response, 78)
	pos, output["Boot Project"] = bin.unpack("z", response, pos)
	pos, output["Project Source Code"] = bin.unpack("z", response, pos) 
	-- close socket and return output table
	socket:close()
	return output
  end
  -- close socket
  socket:close()
  -- return nil
  return nil
end
