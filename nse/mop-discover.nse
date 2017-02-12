local nmap = require "nmap"
local bin = require "bin"
local ipOps = require "ipOps"
local stdnse = require "stdnse"
local packet = require "packet"

description = [[
Detect the Maintenance Operation Protocol (MOP) by sending layer 2 DEC DNA Remote
Console hello/test messages. This protocol is e.g. used on Cisco devices (enabled
by default on various images).

Note: The console can be used with the moprc utility provided by the DECnet for
Linux project.

Further information:
  * http://sourceforge.net/projects/linux-decnet
  * http://linux-decnet.sourceforge.net/docs/doc_index.html
  * https://en.wikipedia.org/wiki/DECnet
]]

author = "Niklaus Schiess <nschiess@ernw.de>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery"}

--
--@args target MAC address of the target
--@args timeout Max time to wait for a response. (default 3s)
--
--@usage
-- nmap --script mop-discover 192.168.1.1
-- nmap --script mop-discover --script-argets target=01:02:03:04:05:06
--
--@output
-- Host script results:
-- |_mop-discover: Maintenance Operation Protocol (MOP) is supported.
--

prerule = function()
  if stdnse.get_script_args(SCRIPT_NAME .. ".target") then
    return true
  else
    return false
  end
end

hostrule = function(host)
  if not host.interface or not host.directly_connected or not host.mac_addr then
    return false
  else
    return true
  end
end

--- Routing control, hello/test message
-- @param source Source MAC address
-- @param target Target MAC address
local build_frame = function(source, target)
  local payload = bin.pack('>CxCx29x7x5',
    0x05, -- Routing flags
    0x05,
    10,
    78
  )
  local p = packet.Frame:new()
  p.mac_src = source.mac
  p.mac_dst = target
  p.ether_type = bin.pack('>S', 0x6002)
  p.buf = payload
  p:build_ether_frame()
  return p.frame_buf
end

--- Send an ethernet frame
-- @param interface Interface which should be used
-- @param frame The raw ethernet frame
local send_ether_frame = function(interface, frame)
  local dnet = nmap.new_dnet()
  dnet:ethernet_open(interface.shortname)
  dnet:ethernet_send(frame)
  dnet:ethernet_close()
end

--- Listens for knx search responses
-- @param interface Network interface to listen on.
-- @param timeout Maximum time to listen.
-- @param result table to put responses into.
local listen_ether = function(interface, timeout, results)
  local condvar = nmap.condvar(results)
  local start = nmap.clock_ms()
  local listener = nmap.new_socket()
  local status, l3data, _

  local filter = 'ether dst ' .. stdnse.format_mac(interface.mac) .. ' and ether proto 0x6002'
  listener:set_timeout(100)
  listener:pcap_open(interface.device, 1024, true, filter)

  while (nmap.clock_ms() - start) < timeout do
    status, _, _, l3data = listener:pcap_receive()
    if status then
      local p = packet.Packet:new(l3data, #l3data)
      table.insert(results, p)
      break
    end
  end
  condvar("signal")
end

action = function(host, port)
  local interface
  local target = stdnse.get_script_args(SCRIPT_NAME .. ".target")
  local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
  timeout = (timeout or 3) * 1000

  if target then
    target = packet.mactobin(target)
    interface = nmap.get_interface()
  else
    target = host.mac_addr
    interface = host.interface
  end

  if interface then
    interface, err = nmap.get_interface_info(interface)
    if not interface then
      stdnse.debug1(err)
      return nil
    end
  else
    stdnse.debug1('Please specify a valid interface.')
    return nil
  end

  local results = {}
  stdnse.new_thread(listen_ether, interface, timeout, results)
  stdnse.sleep(0.5)

  local frame = build_frame(interface, target)
  send_ether_frame(interface, frame)

  local condvar = nmap.condvar(results)
  condvar("wait")

  if #results > 0 then
    return true, "Maintenance Operation Protocol (MOP) is supported."
  else
    return nil
  end
end
