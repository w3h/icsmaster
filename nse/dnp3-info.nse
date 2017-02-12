local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[

This nmap NSE will send a command to query through the first 100 addresses of 
DNP3 to see if a valid response is given. If a valid response is given it will
then parse the results based on function ID and other data. 

]]

---
-- @usage
-- nmap --script dnp3-info -p 20000 <host>

author = "Stephen J. Hilt"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}


--
-- Function to define the portrule as per nmap standards
portrule = shortport.port_or_service(20000, "dnp", "tcp")

-- Datalink Function Codes PRM=0
local function_id = {
[0] = "ACK",
[1] = "NACK",
[11] = "Link Status",
[15] = "User Data"
}
-- Data Link Function Codes PRM=1
local alt_function_id = {
[0] = "RESET Link",
[1] = "Reset User Process",
[2] = "TEST link",
[3] = "User Data",
[4] = "User Data",
[9] = "Request Link Status"
}
-- lookup function codes based off the PRM (byte 2)
function funct_lookup(id)
  local funct_id
  -- if the string is 4 bytes then was 0x0
  if (string.len(id) < 5) then
    -- look up function id in the table, if doesn't exist then its unknown
    funct_id = function_id[tonumber(id,2)] or "Unknown Function ID"
    id = tonumber(id,2)
  -- else byte was 0x??
  else
    local first_value = string.byte(id, 2) % 0x10
    local second_value = tonumber(string.byte(id,5) % 0x10 .. string.byte(id,6) % 0x10 .. string.byte(id,7) %0x10 .. 
        string.byte(id,8) % 0x10,2)
    if( first_value == 0) then
	  -- look up function id in the table, if doesn't exist then its unknown
      funct_id = function_id[second_value] or "Unknown Function ID"
    else
	  -- look up function id in the table, if doesn't exist then its unknown
      funct_id = alt_function_id[second_value] or "Unknown Function ID"
    end
	-- overwrite id to output what the value for if it was 0x??
    id = second_value
  end
  return string.format("%s (%d)", funct_id, id)
end
---
--  Function to set the nmap output for the host, if a valid DNP3 packet
--  is received then the output will show that the port as DNP3  instead of
--  <code>dnp</code>
--
-- @param host Host that was passed in via nmap
-- @param port port that DNP3 is running on (Default TCP/20000)
function set_nmap(host, port)

  --set port Open
  port.state = "open"
  -- set version name to DNP3
  port.version.name = "DNP3"
  nmap.set_port_version(host, port)
  nmap.set_port_state(host, port, "open")

end


---
--  Action Function that is used to run the NSE. This function will send the initial query to the
--  host and port that were passed in via nmap. The initial response is parsed to determine if host
--  is a DNP3 device. If it is then more actions are taken to gather extra information.
--
-- @param host Host that was scanned via nmap
-- @param port port that was scanned via nmap
action = function(host, port)

  
  -- create new socket
  local sock = nmap.new_socket()
  -- set timeout low in case we don't get a response
  sock:set_timeout(1000)
  -- create output table
  local output = stdnse.output_table()
  -- query to pull the fist 100 address 
  local first100 = bin.pack("H", "056405C900000000364C056405C901000000DE8E056405C" .. 
         "9020000009F84056405C9030000007746056405C9040000" ..
	 "001D90056405C905000000F552056405C906000000B4580" .. 
	 "56405C9070000005C9A056405C90800000019B9056405C9" .. 
	 "09000000F17B056405C90A000000B071056405C90B00000" .. 
	 "058B3056405C90C0000003265056405C90D000000DAA705" ..
	 "6405C90E0000009BAD056405C90F000000736F056405C91" ..
	 "000000011EB056405C911000000F929056405C912000000" .. 
	 "B823056405C91300000050E1056405C9140000003A37056" ..
         "405C915000000D2F5056405C91600000093FF056405C917" ..
	 "0000007B3D056405C9180000003E1E056405C919000000D" ..
	 "6DC056405C91A00000097D6056405C91B0000007F140564" ..
	 "05C91C00000015C2056405C91D000000FD00056405C91E00" ..
	 "0000BC0A056405C91F00000054C8056405C920000000014" ..
	 "F056405C921000000E98D056405C922000000A887056405" ..
	 "C9230000004045056405C9240000002A93056405C925000" ..
	 "000C251056405C926000000835B056405C9270000006B99" ..
	 "056405C9280000002EBA056405C929000000C678056405C" ..
	 "92A0000008772056405C92B0000006FB0056405C92C0000" ..
	 "000566056405C92D000000EDA4056405C92E000000ACAE0" ..
	 "56405C92F000000446C056405C93000000026E8056405C9" ..
	 "31000000CE2A056405C9320000008F20056405C93300000" ..
	 "067E2056405C9340000000D34056405C935000000E5F605" ..
	 "6405C936000000A4FC056405C9370000004C3E056405C93" ..
	 "8000000091D056405C939000000E1DF056405C93A000000" ..
	 "A0D5056405C93B0000004817056405C93C00000022C1056" ..
	 "05C93D000000CA03056405C93E0000008B09056405C93F0" ..
	 "0000063CB056405C940000000584A056405C941000000B0" ..
	 "88056405C942000000F182056405C943000000194005640" ..
	 "5C9440000007396056405C9450000009B54056405C94600" ..
	 "0000DA5E056405C947000000329C056405C94800000077B" ..
	 "F056405C9490000009F7D056405C94A000000DE77056405" ..
	 "C94B00000036B5056405C94C0000005C63056405C94D000" ..
	 "000B4A1056405C94E000000F5AB056405C94F0000001D69" ..
	 "056405C9500000007FED056405C951000000972F056405C" .. 
	 "952000000D625056405C9530000003EE7056405C9540000" ..
	 "005431056405C955000000BCF3056405C956000000FDF90" ..
	 "56405C957000000153B056405C9580000005018056405C9" ..
   	 "59000000B8DA056405C95A000000F9D0056405C95B00000" ..
	 "01112056405C95C0000007BC4056405C95D000000930605" ..
	 "6405C95E000000D20C056405C95F0000003ACE056405C96" ..
	 "00000006F49056405C961000000878B056405C962000000" ..
	 "C681056405C9630000002E43056405C9640000004495")
  -- Connect to the remote host
  local constatus, conerr = sock:connect(host, port)
  if not constatus then
    stdnse.debug1(
      'Error establishing a TCP connection for %s - %s', host, conerr
      )
    return nil
  end
 -- send query for the first 100 addresses
 local sendstatus, senderr = sock:send(first100)
  if not sendstatus then
    stdnse.debug1(
      'Error sending dnp3 request to %s:%d - %s',
      host.ip, port.number,  senderr
      )
    return nil
  end
  -- receive the response for parseing
  local rcvstatus, response = sock:receive()
  if(rcvstatus == false) then
    stdnse.debug1( "Receive error: %s", response)
    return nil
  end 
  -- if the response was timeout, then we will return that we had a timeout 
  --(for now add more addresses later)
  if (response == "TIMEOUT" or response == "EOF") then
    sock:close()
    return "TIMEOUT: No response from query"
  end
  -- unpack first two bytes
  local pos, byte1, byte2 = bin.unpack("CC", response, 1)
  -- check to see if it is 0x0564 
  if( byte1 == 0x05 and byte2 == 0x64) then
    -- close socket
    sock:close()
	-- set nmap to reflect open DNP3
    set_nmap(host,port)
	-- unpack bit string for PRM checking as well as function codes
    local pos, ctrl = bin.unpack("B", response, 4)
	-- destination address
    local pos, dstadd = bin.unpack("S", response, 5)
	-- source address
    local pos, srceadd = bin.unpack("S", response, pos)
	-- set up output table with values
    output["Source Address"] = srceadd
    output["Destination Address"] = dstadd
    output["Control"] = funct_lookup(ctrl)
	-- return output
    return output
  -- if non 0x0564 response, then this is not a valid packet. 
  else
    sock:close() 
    return "ERROR: Non Valid DNP3 Packet Response\n\t" .. stdnse.tohex(response)
  end
 
end



