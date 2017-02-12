local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[ This Script is designed to query the I20100 command on Guardian AST Automatic Tank Gauge
products. This script sends a single query and parses the response. This response is the Tank Inventory 
of the ATG. Using --script-args command=I20200 you will be able to pull a diffrent report than the I20100.

Based off of www.veeder.com/gold/download.cfm?doc_id=3668

]]

---
-- @usage
-- nmap --script atg-info -p 10001 <host>
--
-- @args command If set to another command, It will do that command instead of I20100
--
-- @output
--10001/tcp open   Guardian AST reset
--| atg-info:
--| I20100
--| SEP 19, 2015  5:33 PM
--|
--|    Fuel Company
--|    12 Fake St
--|    Anytown, USA 12345
--|
--|
--| IN-TANK INVENTORY
--|
--| TANK PRODUCT             VOLUME TC VOLUME   ULLAGE   HEIGHT    WATER     TEMP
--|   1  UNLEADED              5135         0     6647    42.71     0.00    72.01
--|   2  UNLEADED              5135         0     6647    42.70     0.00    71.55
--|   3  PREMIUM UNLEADED      5135         0     5350    19.27     0.00    72.52
--|_


author = "Stephen J. Hilt"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery"}


--
-- Function to define the portrule as per nmap standards
portrule = shortport.port_or_service(10001, "atg")
---
--  Function to set the nmap output for the host, if a valid ATG packet
--  is received then the output will show that the port as ATG  instead of
--  <code>tcpwrapped</code>
--
-- @param host Host that was passed in via nmap
-- @param port port that ATG is running on (Default TCP/10001)
function set_nmap(host, port)

  --set port Open
  port.state = "open"
  -- set version name to  Guardian AST
  port.version.name = " Guardian AST"
  nmap.set_port_version(host, port)
  nmap.set_port_state(host, port, "open")

end


---
--  Action Function that is used to run the NSE. This function will send the initial query to the
--  host and port that were passed in via nmap. The initial response is parsed to determine if host
--  is a ATG device. If it is then more actions are taken to gather extra information.
--
-- @param host Host that was scanned via nmap
-- @param port port that was scanned via nmap
action = function(host, port)
  local command = "I20100"
  local arguments = stdnse.get_script_args('command')
  if ( arguments ~= "I20100" and arguments ~= nil) then
	command = arguments
  end
  -- create new socket
  local sock = nmap.new_socket()
  -- set timeout low in case we don't get a response
  sock:set_timeout(1000)
  -- query to pull the tank inventory
  local tank_command = "\x01" .. command .. "\n"
  -- Connect to the remote host
  local constatus, conerr = sock:connect(host, port)
  if not constatus then
    stdnse.debug1(
      'Error establishing a TCP connection for %s - %s', host, conerr
      )
    return nil
  end
 -- send query to inventory the tanks
 local sendstatus, senderr = sock:send(tank_command)
  if not sendstatus then
    stdnse.debug1(
      'Error sending ATG request to %s:%d - %s',
      host.ip, port.number,  senderr
      )
    return nil
  end
  -- receive the response for parseing
  local rcvstatus, response = sock:receive_bytes(1024)
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
  -- if the first byte is 0x01, or 0x0a then likely the response is an ATG
  if(string.byte(response,1) == 0x01 or string.byte(response,1) == 0x0a) then
    local inventory_output = string.sub(response,2,-2)
    set_nmap(host, port)
    sock:close()
    return inventory_output
  end
end

