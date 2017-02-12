-- Nmap Scripting Engine
-- required packages for this script
--
-- ICS Discovery Tools Releases
-- ICS Security Workspace(plcscan.org)
---
-- usage:
-- nmap -sT --script dnp3-enumerate.nse -p 20000 <ip>
--
-- Output:
--  PORT      STATE SERVICE REASON
--  20000/tcp open  dnp3    syn-ack
--  | dnp3-enumerate:
--  |   Source address: 20
--  |   Destination address: 0
--  |_  Control code: 68
--
local bin = require "bin"
local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Discovery DNP3 devices the destination address
From http://plcscan.org/blog/2014/12/dnp3-protocol-overview/
]]
author = "Z-0ne"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

function set_nmap(host, port)
	port.state = "open"
	port.version.name = "dnp3"
	port.version.product = "dnp3devices"
	nmap.set_port_version(host, port)
	nmap.set_port_state(host, port, "open")
end

portrule = shortport.port_or_service(20000, "dnp3","tcp")

action = function(host,port)
	local output = stdnse.output_table()
	local settimeout = {timeout=4000}
	local reqlinkstat = bin.pack("H","056405c900000000364c"..
									"056405c901000000de8e"..
									"056405c9020000009f84"..
									"056405c9030000007746"..
									"056405c9040000001d90"..
									"056405c905000000f552"..
									"056405c906000000b458"..
									"056405c9070000005c9a"..
									"056405c90800000019b9"..
									"056405c909000000f17b"..
									"056405c90a000000b071"..
									"056405c90b00000058b3"..
									"056405c90c0000003265"..
									"056405c90d000000daa7"..
									"056405c90e0000009bad"..
									"056405c90f000000736f"..
									"056405c91000000011eb"..
									"056405c911000000f929"..
									"056405c912000000b823"..
									"056405c91300000050e1"..
									"056405c9140000003a37"..
									"056405c915000000d2f5"..
									"056405c91600000093ff"..
									"056405c9170000007b3d"..
									"056405c9180000003e1e"..
									"056405c919000000d6dc"..
									"056405c91a00000097d6"..
									"056405c91b0000007f14"..
									"056405c91c00000015c2"..
									"056405c91d000000fd00"..
									"056405c91e000000bc0a"..
									"056405c91f00000054c8"..
									"056405c920000000014f"..
									"056405c921000000e98d"..
									"056405c922000000a887"..
									"056405c9230000004045"..
									"056405c9240000002a93"..
									"056405c925000000c251"..
									"056405c926000000835b"..
									"056405c9270000006b99"..
									"056405c9280000002eba"..
									"056405c929000000c678"..
									"056405c92a0000008772"..
									"056405c92b0000006fb0"..
									"056405c92c0000000566"..
									"056405c92d000000eda4"..
									"056405c92e000000acae"..
									"056405c92f000000446c"..
									"056405c93000000026e8"..
									"056405c931000000ce2a"..
									"056405c9320000008f20"..
									"056405c93300000067e2"..
									"056405c9340000000d34"..
									"056405c935000000e5f6"..
									"056405c936000000a4fc"..
									"056405c9370000004c3e"..
									"056405c938000000091d"..
									"056405c939000000e1df"..
									"056405c93a000000a0d5"..
									"056405c93b0000004817"..
									"056405c93c00000022c1"..
									"056405c93d000000ca03"..
									"056405c93e0000008b09"..
									"056405c93f00000063cb"..
									"056405c940000000584a"..
									"056405c941000000b088"..
									"056405c942000000f182"..
									"056405c9430000001940"..
									"056405c9440000007396"..
									"056405c9450000009b54"..
									"056405c946000000da5e"..
									"056405c947000000329c"..
									"056405c94800000077bf"..
									"056405c9490000009f7d"..
									"056405c94a000000de77"..
									"056405c94b00000036b5"..
									"056405c94c0000005c63"..
									"056405c94d000000b4a1"..
									"056405c94e000000f5ab"..
									"056405c94f0000001d69"..
									"056405c9500000007fed"..
									"056405c951000000972f"..
									"056405c952000000d625"..
									"056405c9530000003ee7"..
									"056405c9540000005431"..
									"056405c955000000bcf3"..
									"056405c956000000fdf9"..
									"056405c957000000153b"..
									"056405c9580000005018"..
									"056405c959000000b8da"..
									"056405c95a000000f9d0"..
									"056405c95b0000001112"..
									"056405c95c0000007bc4"..
									"056405c95d0000009306"..
									"056405c95e000000d20c"..
									"056405c95f0000003ace"..
									"056405c9600000006f49"..
									"056405c961000000878b"..
									"056405c962000000c681"..
									"056405c9630000002e43"..
									"056405c9640000004495")
	local status, respone = comm.exchange(host, port, reqlinkstat, settimeout)
	if ( status and (#respone > 9) ) then
		local d, protocol_id1 = bin.unpack("C",respone,1)
		local d, protocol_id2 = bin.unpack("C",respone,2)
		if ( protocol_id1 == 0x05 ) then
			if ( protocol_id2 == 0x64 ) then
				local d, dstcode = bin.unpack("C", respone, 7)
				output["Source address"] = dstcode
				local d, srccode = bin.unpack("C", respone, 5)
				output["Destination address"] = srccode
				local d, ctrcode = bin.unpack("C", respone, 4)
				output["Control code"] = ctrcode
				set_nmap(host, port)
				return output
			end
		end
	else
		return nil
	end
end