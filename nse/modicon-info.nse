local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Modicon is a brand of Programmable Logic Controller (PLC) that is put out by
Schneider Electric. This NSE is designed to use Modbus to communicate to the 
PLC via Normal queries that are performed via engineering software. The information
that is collected via Modbus is done in two separate function codes. First, Function 
Code 43 is utilized to pull the Vendor Name, Network Module, and the Firmware Version.
Second, Schneider uses function code 90 for communications as well. Via Function Code 90
it is possible to pull information such as the CPU Module, Memory Card Model, and some 
information about the project that is loaded into the PLC. 


http://digitalbond.com
]]
---
-- @usage
-- nmap --script modicon-info -p 502 <host>
--
--
-- @output
--502/tcp open  Modbus
--| modicon-info:
--|   Vendor Name: Schneider Electric
--|   Network Module: BMX NOE 0100
--|   CPU Module: BMX P34 2000
--|   Firmware: V2.60
--|   Memory Card: BMXRMS008MP
--|   Project Information: Project -  V4.0
--|   Project File Name: Project.STU
--|   Project Revision: 0.0.9 
--|_  Project Last Modified: 7/11/2013 5:55:33
-- @xmloutput
--<elem key="Vendor Name">Schneider Electric</elem>
--<elem key="Network Module">BMX NOE 0100</elem>
--<elem key="CPU Module">BMX P34 2000</elem>
--<elem key="Firmware">V2.60</elem>
--<elem key="Memory Card">BMXRMS008MP</elem>
--<elem key="Project Information">Project -  V4.0</elem>
--<elem key="Project File Name">Project.STU</elem>
--<elem key="Project Revision">0.0.9</elem>
--<elem key="Project Last Modified">7/11/2013 5:55:33</elem>

author = "Stephen Hilt (Digital Bond)"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive","digitalbond"}

--
-- Function to define the portrule as per nmap standards
--
--
--
portrule = shortport.portnumber(502, "tcp")

---
--  Function to trim white space off the beginning and ending of a string
-- 
-- @param s a string passed in that needs white space trimmed off
function trim(s)
  -- remove white spaces from beginning and ending of the string
  return (s:gsub("^%s*(.-)%s*$", "%1"))
end
---
--  Function to set the nmap output for the host, if a valid Modbus packet
--  is received then the output will show that the port as Modbus.
-- 
-- @param host Host that was passed in via nmap
-- @param port port that Modbus is running on (Default TCP/502)
function set_nmap(host, port)

  --set port Open
  port.state = "open"
  -- set version name to Modbus
  port.version.name = "Modbus"
  nmap.set_port_version(host, port)
  nmap.set_port_state(host, port, "open")

end
---
--  Function to setup the communications to the Modicon. This is where alot
--  of the function code 90 information is sent and parsed for information
--  about the Modicon itself. 
--
-- @param socket Socket passed in via Action to communicate to remote device
-- @param output The output table to add information that is collected
---
function init_comms(socket, output)

  -- decelerations
  local pos
  local payload = bin.pack("H","000100000004005a0002")
  socket:send(payload)
  -- recv packet, however not going to do anything with it
  local rcvstatus, response = socket:receive() 
  -- send and receive, not going to do anything with this packet. 
  payload = bin.pack("H","000200000005005a000100")
  socket:send(payload)
  local rcvstatus, response = socket:receive() 
  -- create a string with 249 T (0x54)
  local count = 0
  local ice = "54"
  while (count < 248) do 
    ice = ice .. "54"
	count = count + 1
  end
  -- send packet with 249 T's (0x54), recv packet and do nothing as well
  payload = bin.pack("H","0003000000fe005a00fe00" .. ice)
  socket:send(payload)
  local rcvstatus, response = socket:receive() 
  -- send packet that request the project information
  payload = bin.pack("H","000400000005005a000300")
  socket:send(payload)
  local rcvstatus, response = socket:receive() 
  -- unpack the Project Name, this is configured by the engineers
  local pos, project_name = bin.unpack("z", response, 50)
  -- unpack the year that the project was last modified
  -- define the next sections we are going to unpack 
  -- Each one is to support time stamp
  local project_hour
  local project_min
  local project_sec
  local project_month
  local project_day
  -- define the 3 vars for the project revision number
  local project_rev_1
  local project_rev_2
  local project_rev_3
  -- unpack the time stamp, as well as the revision numbers
  -- unpack the seconds
  pos, project_sec = bin.unpack("C", response, 38)
  -- unpack the min
  pos, project_min = bin.unpack("C", response, pos)
  -- unpack the hour
  pos, project_hour = bin.unpack("C", response, pos)
  -- unpack the day
  pos, project_day = bin.unpack("C", response, pos)
  -- unpack the month
  pos, project_month = bin.unpack("C", response, pos)
  pos, project_year = bin.unpack("<S", response, pos)
  -- The next 3 are for the revision number
  pos, project_rev_1 = bin.unpack("C", response, pos )
  pos, project_rev_2 =  bin.unpack("C", response, pos)
  pos, project_rev_3 =  bin.unpack("C", response, pos)
  
  
  payload = bin.pack("H","000500000005005a000304")
  socket:send(payload)
  local rcvstatus, response = socket:receive() 
	
  payload = bin.pack("H","000600000004005a0004")
  socket:send(payload)
  local rcvstatus, response = socket:receive() 
	
  payload = bin.pack("H","000700000005005a000100")
  socket:send(payload)
  local rcvstatus, response = socket:receive() 
	
  payload = bin.pack("H","0008000000fe005a000a00000102030405060708090a0b0c0d0e0f10111213141516" .. 
    "1718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243" ..
	"4445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70" ..
	"7172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d" ..
	"9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9ca" ..
	"cbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8")
  socket:send(payload)
  local rcvstatus, response = socket:receive() 
	
  payload = bin.pack("H","000900000004005a0004")
  socket:send(payload)
  local rcvstatus, response = socket:receive() 
	
  payload = bin.pack("H","000a00000004005a0004")
  socket:send(payload)
  local rcvstatus, response = socket:receive() 
	
  payload = bin.pack("H","000b00000004005a0004")
  socket:send(payload)
  local rcvstatus, response = socket:receive() 
	
  payload = bin.pack("H","000c0000000d005a0020001300000000006400")
  socket:send(payload)
  local rcvstatus, response = socket:receive() 
	
  payload = bin.pack("H","000d0000000d005a0020001300640000009c00")
  socket:send(payload)
  local rcvstatus, response = socket:receive() 
	
  payload = bin.pack("H","000e0000000d005a0020001400000000006400")
  socket:send(payload)
  local rcvstatus, response = socket:receive() 
	
  payload = bin.pack("H","000f0000000d005a002000140064000000f600")
  socket:send(payload)
  local rcvstatus, response = socket:receive() 
  local pos, size = bin.unpack("C", response, 6)
  -- calcualate size of packet, from the starting point we will be reading
  local project_info = ""
  local tmp_proj_info
  local pos 
  -- for loop that iterates at byte 180 to the end of the packet 
  -- the size of the packet is off by 6 since the length field is 6 bytes
  -- into the packet
  for pos=180,size+6 do
	-- if pos is equal to nil or 0x00 
	pos, tmp_proj_info = bin.unpack("A", response, pos)
	if (tmp_proj_info == nil or stdnse.tohex(tmp_proj_info) == "00") then
	  pos = pos + 1
	  project_info = project_info .. " "
	-- else store results
	else
	  project_info = project_info  ..  tmp_proj_info
	end
  end
  -- define and unpack the project file name
  local project_fn
  payload = bin.pack("H","00100000000d005a00200014005a010000f600")
  socket:send(payload)
  local rcvstatus, response = socket:receive() 
  -- parse the project filename
  pos, project_fn = bin.unpack("z", response, 14)
  -- if nil then set some value, other wise we will have issues concatenating strings
  if(project_fn == nil) then
	project_fn = ""
  end
  -- store information into the output table to be shown in nmap results  
  output["Project Information"] = project_name .. " - " .. trim(project_info) .. project_fn
  output["Project Revision"] =  project_rev_3 .. "." .. project_rev_2 .. "." .. project_rev_1
  output["Project Last Modified"] = project_month .. "/" .. project_day .. "/" .. project_year .. 
    " " .. project_hour .. ":" .. project_min .. ":" .. project_sec
  -- return output
  return output
  	
end

---
--  Action Function that is used to run the NSE. This function will send the initial query to the
--  host and port that were passed in via nmap. The initial response is parsed to determine if host
--  is a Modbus/Modicon device. If it is then more actions are taken to gather extra information.
-- 
-- @param host Host that was scanned via nmap
-- @param port port that was scanned via nmap
action = function(host,port)
  -- Function code 43 (0x2b), read device identification (14 - 0x0e)
  local modbus_req_ident = bin.pack("H","000000000005002b0e0200")
  -- Function Code 90 (0x5a) request CPU and Request Memory
  local modbus_req_cpu = bin.pack("H","000100000004005a0002")
  local modbus_req_mem = bin.pack("H","01bf00000005005a000606")
  -- create new output table in Nmap format  
  local output = stdnse.output_table()
  local revision = nil
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
  -- initialise communications
  -- send read device identification
  try(socket:send(modbus_req_ident))
  local rcvstatus, response = socket:receive()
  if(rcvstatus == false) then
    return false, response
  end
  local pos, status = bin.unpack("C", response, 9) 
  if (status == 0x07) then
    set_nmap(host, port)
	return "\n\tUnknown Exception Code"
  end
  -- parse out the number of responses 
  local pos, numresponses = bin.unpack("C", response, 14)
  if (numresponses == 0x03) then
    set_nmap(host, port)
    local pos, size = bin.unpack("C", response, 16)
	pos, output["Vendor Name"] = bin.unpack("A" .. size, response, 17)
	pos, size = bin.unpack("C", response, pos + 1) 
	pos, output["Network Module"] = bin.unpack("A" .. size, response, pos) 
	pos, size = bin.unpack("C", response, pos + 1)
	pos, revision = bin.unpack("A" .. size, response, pos)
	if (string.sub(output["Vendor Name"], 1, 9) == "Schneider") then
	  
	  try(socket:send(modbus_req_cpu))
      local rcvstatus, response = socket:receive()
      if(rcvstatus == false) then
        return false, response
      end
	  local pos, status = bin.unpack("C", response, 9)
	  if (status == 0x01) then
	    output["Firmware"] = revision
	    return output
	  end
	  pos, size = bin.unpack("C", response, 33) 
	  pos, output["CPU Module"] = bin.unpack("A" .. size, response, pos) 
	  output["Firmware"] = revision
	  
	  try(socket:send(modbus_req_mem))
	  local rcvstatus, response = socket:receive()
      if(rcvstatus == false) then
        return false, response
      end
	  pos, size = bin.unpack("C", response, 17)
	  if(size ~= nil) then
	    pos, output["Memory Card"] = bin.unpack("A" .. size, response, pos)
	  end
	  output = init_comms(socket, output)
	  --output = read_ladder(socket, output)
	  socket:close()
	  -- for each element in the table, if it is nil, then remove the information from the table
      for key, value in pairs(output) do
        if(string.len(output[key]) == 0) then
          output[key] = nil
        end
      end
	  
	  return output
	else
	  socket:close()
	  return nil
	end
  else
    socket:close()
	return nil
  end
end
