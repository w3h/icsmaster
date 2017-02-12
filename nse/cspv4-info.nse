local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
This NSE script is used to send a CSPV4 packet to a remote device that has TCP 2222 open. This is a port used via CIP
and used by CSPV4 on AB PLC5 systems. This will determine the Session ID of the remote device to verify it as a CSPV4
compliant device.  CSPV4 or AB/Ethernet is used by Allen Bradley inside of its software products such as RSLinx to 
communicate to the PLCs. This will help ideitify some Allen Bradley PLCs that do not communicate via Ethernet/IP. 
Example: PLC5, SLC 500

]]
---
-- @usage
-- nmap --script cspv4-info -p 2222 <host>
--
--
-- @output
--PORT     STATE SERVICE
--2222/tcp open  CSPV4
--| cspv4-info: 
--|_  Session ID: 65792

author = "Stephen Hilt"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

--
-- Function to define the portrule as per nmap standards
--
--
--
portrule = shortport.portnumber(2222, "tcp")

---
--  Function to set the nmap output for the host, if a valid CSPV4 packet
--  is received then the output will show that the port as CSPV4 instead of 
--  <code>unknown</code>
-- 
-- @param host Host that was passed in via nmap
-- @param port port that CSPV4 is running on (Default TCP/2222)
function set_nmap(host, port)

  --set port Open
  port.state = "open"
  -- set version name to cspv4
  port.version.name = "CSPV4"
  nmap.set_port_version(host, port)
  nmap.set_port_state(host, port, "open")

end
---
--  Action Function that is used to run the NSE. 
-- 
-- @param host Host that was scanned via nmap
-- @param port port that was scanned via nmap
action = function(host,port)
  -- pack the inital communications to the PLC5
  local init_coms = bin.pack("H","01010000000000000000000000040005000000000000000000000000")
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
  
  -- connect to port on host
  try(socket:connect(host, port))
  -- send Req Identity packet
  try(socket:send(init_coms))
  -- receive response
  local rcvstatus, response = socket:receive()
   if(rcvstatus == false) then
    return false, response
  end
  -- unpack the response first byte
  local pos, first_check = bin.unpack("C", response, 1)
  -- Validate the response is the response we expected 
  if(first_check == 0x02) then
    -- store Session ID in output table 
    pos, output["Session ID"] = bin.unpack("i", response, 5)
    -- set Nmap output
    set_nmap(host, port)
    -- close socket
    socket:close()
    -- return output table to Nmap
    return output
  -- If response is not what expcted then close connection and return nothing
  else
    socket:close()
    return nil
  end  
end
