local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
This NSE script is used to send a FINS packet to a remote device that
has UDP 9600 open. The script will send a Controller Data Read Command and once a
response is received, it validates that it was a proper response to the command
that was sent, and then will parse out the data. 

http://digitalbond.com

]]
---
-- @usage
-- nmap --script ormonudp-info -sU -p 9600 <host>
--
--
--
-- @output
--9600/tcp open  OMRON FINS
--| omrontcp-info:
--|   Controller Model: CJ2M-CPU32          02.01
--|   Controller Version: 02.01
--|   For System Use:
--|   Program Area Size: 20
--|   IOM size: 23
--|   No. DM Words: 32768
--|   Timer/Counter: 8
--|   Expansion DM Size: 1
--|   No. of steps/transitions: 0
--|   Kind of Memory Card: 0
--|_  Memory Card Size: 0

-- @xmloutput
--<elem key="Controller Model">CS1G_CPU44H         03.00</elem>
--<elem key="Controller Version">03.00</elem>
--<elem key="For System Use"></elem>
--<elem key="Program Area Size">20</elem>
--<elem key="IOM size">23</elem>
--<elem key="No. DM Words">32768</elem>
--<elem key="Timer/Counter">8</elem>
--<elem key="Expansion DM Size">1</elem>
--<elem key="No. of steps/transitions">0</elem>
--<elem key="Kind of Memory Card">0</elem>
--<elem key="Memory Card Size">0</elem>


author = "Stephen Hilt (Digital Bond)"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "version"}

--
-- Function to define the portrule as per nmap standards
--
--
portrule = shortport.portnumber(9600, "udp")

---
--  Function to set the nmap output for the host, if a valid OMRON FINS packet
--  is received then the output will show that the port is open instead of
--  <code>open|filtered</code>
--
-- @param host Host that was passed in via nmap
-- @param port port that FINS is running on (Default UDP/9600)
function set_nmap(host, port)

  --set port Open
  port.state = "open"
  -- set version name to OMRON FINS
  port.version.name = "OMRON FINS"
  nmap.set_port_version(host, port)
  nmap.set_port_state(host, port, "open")

end

local memcard = {
  [0] = "No Memory Card",
  [1] = "SPRAM",
  [2] = "EPROM",
  [3] = "EEPROM"
}

function memory_card(value)
  local mem_card = memcard[value] or "Unknown Memory Card Type"
  return mem_card
end

---
--  Action Function that is used to run the NSE. This function will send the initial query to the
--  host and port that were passed in via nmap. The initial response is parsed to determine if host
--  is a FINS supported device. 
--
-- @param host Host that was scanned via nmap
-- @param port port that was scanned via nmap
action = function(host,port)
  -- 0501 is the command to read the Controller Data
  -- This command via UDP will result
  local controller_data_read = bin.pack("H", "800002000000006300ef050100")
     
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
  -- send Request Information Packet
  try(socket:send(controller_data_read))
  local rcvstatus, response = socket:receive()
  if(rcvstatus == false) then
    return false, response
  end
  local pos, header = bin.unpack("C", response, 1) 
  if(header == 0xc0 or header == 0xc1) then
	set_nmap(host, port)
	local response_code
    pos, response_code = bin.unpack("<S", response, 13)
	-- test for a few of the error codes I saw when testing the script
	if(response_code == 2081) then
	  output["Response Code"] = "Data cannot be changed (0x2108)"
	elseif(response_code == 290) then
	  output["Response Code"] = "The mode is wrong (executing) (0x2201)"
	-- if a successful response code then
	elseif(response_code == 0) then
	  -- parse information from response
	  pos, output["Response Code"] = "Normal completion (0x0000)"
	  pos, output["Controller Model"] = bin.unpack("z", response,15) 
	  pos, output["Controller Version"] = bin.unpack("z", response, 35)
	  pos, output["For System Use"] = bin.unpack("z", response, 55)
	  pos, output["Program Area Size"] = bin.unpack(">S", response, 95)
	  pos, output["IOM size"] = bin.unpack("C", response, pos)
	  pos, output["No. DM Words"] = bin.unpack(">S", response, pos)
	  pos, output["Timer/Counter"] = bin.unpack("C", response, pos)
	  pos, output["Expansion DM Size"] = bin.unpack("C", response, pos)
	  pos, output["No. of steps/transitions"] = bin.unpack(">S", response, pos)
	  local mem_card_type
	  pos, mem_card_type = bin.unpack("C", response, pos)
	  output["Kind of Memory Card"] = memory_card(mem_card_type)
	  pos, output["Memory Card Size"] = bin.unpack(">S", response, pos) 

	else 
	  output["Response Code"] = "Unknown Response Code"
	end
	socket:close()
	return output
		
  else
	socket:close()
	return nil
  end

end
