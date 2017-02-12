description = [[
    Attemts to check tcp/2404 port supporting IEC 60870-5-104 ICS protocol.
]]

---
-- @usage
-- nmap -Pn -n -d --script iec-identify.nse  --script-args='iec-identify.timeout=500' -p 2404 <host>
--
-- @args iec-identify.timeout
--       Set the timeout in milliseconds. The default value is 500.
--
-- @output
-- PORT     STATE SERVICE         REASON
-- 2404/tcp open  IEC 60870-5-104 syn-ack
-- | iec-identify:
-- |   testfr sent / recv: 680443000000 / 680483000000
-- |   startdt sent / recv: 680407000000 / 68040b000000
-- |   c_ic_na_1 sent / recv: 680e0000000064010600ffff00000000 / 680e0000020064014700ffff00000014
-- |_  asdu address: 65535
--
-- Version 0.1
--
---

author = "Aleksandr Timorin"
copyright = "Aleksandr Timorin"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

local shortport = require("shortport")
local bin = require("bin")
local comm = require("comm")
local stdnse = require("stdnse")

portrule = shortport.portnumber(2404, "tcp")

local function hex2str(str)
    local x = {}
    local char_int
    for y in str:gmatch('(..)') do
        char_int = tonumber(y, 16)
        if char_int>=32 and char_int<=126 then
          x[#x+1] = string.char( char_int )
        else
          x[#x+1] = y
        end
    end
    return table.concat( x )
end

action = function(host, port)
  
  local timeout = stdnse.get_script_args("iec-identify.timeout")
  timeout = tonumber(timeout) or 500

  local asdu_address
  local pos
  local status, recv
  local output = {}
  local socket = nmap.new_socket()

  socket:set_timeout(timeout)

  -- attempt to connect tp 2404 tcp port
  stdnse.print_debug(1, "try to connect to port 2404" )
  status, result = socket:connect(host, port, "tcp")
  --stdnse.print_debug(1, "connect status %s", status )
  if not status then
    return nil
  end

  -- send TESTFR command
  local TESTFR = string.char(0x68, 0x04, 0x43, 0x00, 0x00, 0x00)
  status = socket:send( TESTFR )
  stdnse.print_debug(1, "testfr status %s", status )
  if not status then
    return nil
  end
  
  -- receive TESTFR answer
  status, recv = socket:receive_bytes(1024)
  stdnse.print_debug(1, "testfr recv: %s", stdnse.tohex(recv) )
  --table.insert(output, string.format("testfr sent / recv: %s / %s", hex2str( stdnse.tohex(TESTFR)), hex2str( stdnse.tohex(recv))))
  table.insert(output, string.format("testfr sent / recv: %s / %s", stdnse.tohex(TESTFR), stdnse.tohex(recv)))

  -- send STARTDT command
  local STARTDT = string.char(0x68, 0x04, 0x07, 0x00, 0x00, 0x00)
  status = socket:send( STARTDT )
  if not status then
    return nil
  end

  -- receive STARTDT answer
  status, recv = socket:receive_bytes(0)
  stdnse.print_debug(1, "startd recv len: %d", #recv )
  stdnse.print_debug(1, "startdt recv: %s", stdnse.tohex(recv) )
  --table.insert(output, string.format("startdt sent / recv: %s / %s", hex2str( stdnse.tohex(STARTDT)), hex2str( stdnse.tohex(recv))))
  table.insert(output, string.format("startdt sent / recv: %s / %s", stdnse.tohex(STARTDT), stdnse.tohex(recv)))

  -- if received 2 packets - STARTDT con + ME_EI_NA_1 Init -> full length should be 6+6+10 bytes
  if #recv == 22 then
    pos, asdu_address = bin.unpack("<S", recv, 17 )
  else
    -- send C_IC_NA_1 command
	local C_IC_NA_1_broadcast = string.char(0x68, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x64, 0x01, 0x06, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x14)
	status = socket:send( C_IC_NA_1_broadcast )
    stdnse.print_debug(1, "c_ic_na_1 status %s", status )
    if not status then
      return nil
    end
	
	-- receive C_IC_NA_1 answer
	status, recv = socket:receive_bytes(0)
	stdnse.print_debug(1, "c_ic_na_1 recv len: %d", #recv )
    stdnse.print_debug(1, "c_ic_na_1 recv: %s", stdnse.tohex(recv) )
    table.insert(output, string.format("c_ic_na_1 sent / recv: %s / %s", stdnse.tohex(C_IC_NA_1_broadcast), stdnse.tohex(recv)))
	if #recv == 16 then
	  pos, asdu_address = bin.unpack("<S", recv, 11 )
	end
  end

  if asdu_address then
    table.insert(output, string.format("asdu address: %d", asdu_address))
  end

  if(#output == 4 and asdu_address) then
    port.version.name = "IEC 60870-5-104"
    nmap.set_port_state(host, port, "open")
    nmap.set_port_version(host, port, "hardmatched")        
    return stdnse.format_output(true, output)
  else
    return nil
  end

end
