local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[

Tridium Niagara Fox is a protocol used within Building Automation Systems. Based
off Billy Rios and Terry McCorkle's work this Nmap NSE will collect information
from A Tridium Niagara system. The information is collected via TCP/1911, 
the default Tridium Niagara Fox Port.  

http://digitalbond.com

]]

---
-- @usage
-- nmap --script fox-info.nse -p 1911 <host>
--
-- @args aggressive - boolean value defines find all or just first sid
--
-- @output
-- 1911/tcp open  Niagara Fox
-- | fox-info: 
-- |   Fox Version: 1.0.1
-- |   Host Name: xpvm-0omdc01xmy
-- |   Host Address: 192.168.1.1
-- |   Application Name: Workbench
-- |   Application Version: 3.7.44
-- |   VM Name: Java HotSpot(TM) Server VM
-- |   VM Version: 20.4-b02
-- |   OS Name: Windows XP
-- |   Time Zone: America/Chicago
-- |   Host ID: Win-99CB-D49D-5442-07BB
-- |   VM UUID: 8b530bc8-76c5-4139-a2ea-0fabd394d305
-- |_  Brand ID: vykon
--
-- @xmloutput
--<elem key="Fox Version">1.0.1</elem>
--<elem key="Host Name">xpvm-0omdc01xmy</elem>
--<elem key="Host Address">192.168.1.1</elem>
--<elem key="Application Name">Workbench</elem>
--<elem key="Application Version">3.7.44</elem>
--<elem key="VM Name">Java HotSpot(TM) Server VM</elem>
--<elem key="VM Version">20.4-b02</elem>
--<elem key="OS Name">Windows XP</elem>
--<elem key="Time Zone">America/Chicago</elem>
--<elem key="Host ID">Win-99CB-D49D-5442-07BB</elem>
--<elem key="VM UUID">8b530bc8-76c5-4139-a2ea-0fabd394d305</elem>
--<elem key="Brand ID">vykon</elem>

author = "Stephen Hilt (Digital Bond)"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}


--
-- Function to define the portrule as per nmap standards
--
--
--

portrule = shortport.port_or_service(1911, "mtp", "tcp")

--
-- Function to split a string based on a separator
-- 
-- @param sep A separator to split the string upon
function string:split(sep)
  local sep, fields = sep or ":", {}
  local pattern = string.format("([^%s]+)", sep)
  self:gsub(pattern, function(c) fields[#fields+1] = c end)
  return fields
end

---
--  Function to set the Nmap output for the host, if a valid Niagara Fox packet
--  is received then the output will show that the port is open instead of
--  <code>open|filtered</code>
--
-- @param host Host that was passed in via nmap
-- @param port port that Niagara Fox is running on (Default UDP/47808)
function set_nmap(host, port)

  --set port Open
  port.state = "open"
  -- set version name to Niagara Fox
  port.version.name = "Niagara Fox"
  nmap.set_port_version(host, port)
  nmap.set_port_state(host, port, "open")

end

--
-- Function to term the length of a table/array
-- 
-- @param t a table that is passed in
function len(t)
  count = 0
  for k,v in pairs(t) do
     count = count + 1
  end
  return count
end

---
--  Action Function that is used to run the NSE. This function will send the 
--  initial query to the host and port that were passed in via nmap. The 
--  initial response is parsed to determine if host is a Niagara Fox device. If it 
--  is then more actions are taken to gather extra information.
--
-- @param host Host that was scanned via nmap
-- @param port port that was scanned via nmap
action = function(host, port)
  --set the first query data for sending
  local orig_query = bin.pack( "H","666f7820612031202d3120666f782068656c6c6f0a7b0a" ..
                     "666f782e76657273696f6e3d733a312e300a69643d693a310a686f73744e" ..
		     "616d653d733a7870766d2d306f6d64633031786d790a686f737441646472" ..
		     "6573733d733a3139322e3136382e312e3132350a6170702e6e616d653d73" ..
		     "3a576f726b62656e63680a6170702e76657273696f6e3d733a332e372e34" .. 
		     "340a766d2e6e616d653d733a4a61766120486f7453706f7428544d292053" ..
		     "657276657220564d0a766d2e76657273696f6e3d733a32302e342d623032" ..
		     "0a6f732e6e616d653d733a57696e646f77732058500a6f732e7665727369" ..
		     "6f6e3d733a352e310a6c616e673d733a656e0a74696d655a6f6e653d733a" ..
		     "416d65726963612f4c6f735f416e67656c65733b2d32383830303030303b" .. 
		     "333630303030303b30323a30303a30302e3030302c77616c6c2c6d617263" .. 
		     "682c382c6f6e206f722061667465722c73756e6461792c756e646566696e" ..
		     "65643b30323a30303a30302e3030302c77616c6c2c6e6f76656d6265722c" ..
		     "312c6f6e206f722061667465722c73756e6461792c756e646566696e6564" ..
		     "0a686f737449643d733a57696e2d393943422d443439442d353434322d30" ..
		     "3742420a766d557569643d733a38623533306263382d373663352d343133" ..
		     "392d613265612d3066616264333934643330350a6272616e6449643d733a" ..
		     "76796b6f6e0a7d3b3b0a" )
  -- output table that will be returned to nmap
  local to_return = stdnse.output_table()

  -- create new socket
  local sock = nmap.new_socket()
  -- connect to the remote host
  local constatus, conerr = sock:connect(host, port)
  if not constatus then
    stdnse.debug1(
      'Error establishing a UDP connection for %s - %s', host, conerr
      )
    return nil
  end
  -- send the original query to see if it is a valid Niagara Fox Device
  local sendstatus, senderr = sock:send(orig_query)
  if not sendstatus then
    stdnse.debug1(
      'Error sending Niagara Fox request to %s:%d - %s',
      host.ip, port.number,  senderr
      )
    return nil
  end

  -- receive response
  local rcvstatus, response = sock:receive()
  if(rcvstatus == false) then
    stdnse.debug1( "Receive error: %s", response)
    return nil
  end
  -- split the response on 0x0a (NL char)
  local output = response:split("\x0a")
  -- for each value in side of the created array
  for keys,value in pairs(output) do
    -- if string contains hostName
    if ( string.match(value, "hostName") ) then
      local temp = value:split(":")
      to_return["Host Name"] = temp[2]
	-- if response contains hostAddress
    elseif (string.match(value, "hostAddress") ) then
      local temp = value:split(":")
      to_return["Host Address"] = temp[2]
	-- if response contains fox.version
    elseif ( string.match(value, "fox.version") ) then
      local temp = value:split(":")
      to_return["Fox Version"] = temp[2]
	-- if response contains app.name
    elseif ( string.match(value, "app.name") ) then
      local temp = value:split(":")
      to_return["Application Name"] = temp[2]
	-- if response contains app.version
    elseif ( string.match(value,"app.version") ) then
      local temp = value:split(":")
      to_return["Application Version"] = temp[2]
	-- if response contains vm.name
    elseif ( string.match(value, "vm.name") ) then
      local temp = value:split(":")
      to_return["VM Name"] = temp[2]
	-- if response contains vm.version
    elseif ( string.match(value, "vm.version") ) then
      local temp = value:split(":") 
      to_return["VM Version"] = temp[2]
	--if response contains os.name
    elseif ( string.match(value,"os.name") ) then 
      local temp = value:split(":")
      to_return["OS Name"] = temp[2]
	-- if response contains timeZone
    elseif (string.match(value,"timeZone") ) then
      local temp = value:split(":")
	  -- split again just for the timezone name
      local temp2 = temp[2]:split(";")
    -- if response contains hostId
    elseif ( string.match(value,"hostId") ) then
      local temp = value:split(":")
      to_return["Host ID"] = temp[2]
	-- if response contains vmUuid
    elseif ( string.match(value,"vmUuid") ) then
      local temp = value:split(":")
      to_return["VM UUID"] = temp[2]
	-- if response contains brandId
    elseif ( string.match(value, "brandId") ) then 
      local temp = value:split(":")
      to_return["Brand ID"] = temp[2]
    end 
    -- if the length of the table is 0, then we didn't parse anything
    if( len(to_return) ~= 0 ) then 
	  -- set nmap output if we did parse information
      set_nmap(host,port)
    end
  end
  -- return output table to nmap 
  return to_return
end

