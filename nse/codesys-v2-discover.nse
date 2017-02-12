local nmap   = require "nmap"
local comm   = require "comm"
local stdnse = require "stdnse"
local strbuf = require "strbuf"
local nsedebug = require "nsedebug"

description = [[

http://digitalbond.com

]]

author = "Stephen Hilt (Digital Bond)"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

---
-- Script is executed for any TCP port.
portrule = function( host, port )
  return port.protocol == "tcp"
end

---
--  Function to set the nmap output for the host, if a valid CoDeSyS packet
--  is received then the output will show that the port as CoDeSyS 
--
-- @param host Host that was passed in via nmap
-- @param port port that CoDeSyS may be running on TCP/1200 or TCP/2455
function set_nmap(host, port)

  --set port Open
  port.state = "open"
  -- set version name to CoDeSyS
  port.version.name = "CoDeSyS"
  nmap.set_port_version(host, port)
  nmap.set_port_state(host, port, "open")

end

---
--  Remove extra whitespace from the beginning and end the string
--
-- @param s string to remove extra white space

function trim(s)
  -- remove white spaces from beginning and ending of the string
  return (s:gsub("^%s*(.-)%s*$", "%1"))
end

---
--  Action Function that is used to run the NSE. This function will send the initial query to the
--  host and port that were passed in via nmap. The initial response is parsed to determine if host
--  is a CoDeSys device. If it is then more actions are taken to gather extra information.
--
-- @param host Host that was scanned via nmap
-- @param port port that was scanned via nmap
action = function( host, port )
  -- little endian query
  lile_query = bin.pack("H", "bbbb0100000001")
  -- big endian query
  bige_query = bin.pack("H", "bbbb0100000101")
  -- set up table for output
  local output = stdnse.output_table()
  -- create socket
  local sock = nmap.new_socket()
  -- connect to remote host
  local constatus, conerr = sock:connect(host, port)
  -- if not successful debug error message and return nil
  if not constatus then
    stdnse.print_debug(1,
      'Error establishing a TCP connection for %s - %s', host, conerr
      )
    return nil
  end
  -- send little endian query
  local sendstatus, senderr = sock:send(lile_query)
  if not sendstatus then
    stdnse.print_debug(1,
      'Error sending CoDeSyS request to %s:%d - %s',
      host.ip, port.number,  senderr
      )
     return nil
  end
  -- recieve response
  local rcvstatus, response = sock:receive()
  if(rcvstatus == false) then
    stdnse.print_debug(1, "Receive error: %s", response)
    return nil
  end
  -- if there was no response, try big endian
  if(response == "EOF" or response == "TIMEOUT") then
    -- try sending big endian query
    local sendstatus, senderr = sock:send(bige_query)
    if not sendstatus then
      stdnse.print_debug(1,
        'Error sending CoDeSyS request to %s:%d - %s',
        host.ip, port.number,  senderr
        )
      return nil
    end
    -- receive response
    local rcvstatus, response = sock:receive()
    if(rcvstatus == false) then
      stdnse.print_debug(1, "Receive error: %s", response)
      return nil
    end
  end
  -- unpack first byte to see if it is 0xbb
  local pos, codesys_check = bin.unpack("C", response, 1)
  -- is first byte 0xbb?
  if (codesys_check ~= 0xbb) then
    sock:close()
    return nil
  end 

  local pos, os_name = bin.unpack("z", response, 65)
  local pos , os_type = bin.unpack("z", response, 97)
  local pos, product_type = bin.unpack("z", response, 129)
  -- close socket
  sock:close()
  -- set nmap port
  set_nmap(host, port)
  -- set output table (for future growth of information)
  output["OS Name"] = os_name .. " " .. os_type
  output["Product Type"] = product_type
  -- return output table to nmap
  return output
end 
