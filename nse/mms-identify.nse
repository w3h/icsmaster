description = [[
    Attemts to check tcp/102 port supporting iec-61850-8-1 (mms) ics protocol. Send identify request and extract vendor name, model name, revision from response.
]]

---
-- @usage
-- nmap -d --script mms-identify.nse  --script-args='mms-identify.timeout=500' -p 102 <host>
--
-- @args mms-identify.timeout
--       Set the timeout in milliseconds. The default value is 500.
--
-- @output
-- PORT    STATE SERVICE
-- 102/tcp open  iso-tsap?
-- | mms-identify:
-- |   Raw answer: 030000>02f08001000100a10/020103a0*a1(020101a2#800flibiec61850.com810blibiec6185082030.5
-- |   Vendor name: libiec61850.com
-- |   Model name: libiec61850
-- |_  Revision: 0.5
--
-- Version 0.3
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

portrule = shortport.portnumber(102, "tcp")

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
  
  local timeout = stdnse.get_script_args("mms-identify.timeout")
  timeout = tonumber(timeout) or 500

  local status, recv
  local output = {}
  local socket = nmap.new_socket()

  socket:set_timeout(timeout)

  status, result = socket:connect(host, port, "tcp")
  if not status then
    return nil
  end

  local CR_TPDU = string.char(0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0xff, 0xff, 0xff, 0xff, 0x00)
  -- status, recv = comm.exchange(host, port, CR_TPDU, {timeout=timeout})
  status = socket:send( CR_TPDU )
  if not status then
    return nil
  end
  status, recv = socket:receive_bytes(1024)
  stdnse.print_debug(1, "cr_tpdu recv: %s", stdnse.tohex(recv) )
  table.insert(output, string.format("cr_tpdu send / recv: %s / %s", hex2str( stdnse.tohex(CR_TPDU)), hex2str( stdnse.tohex(recv))))

  local MMS_INITIATE = string.char(
        0x03, 0x00, 0x00, 0xc5, 0x02, 0xf0, 0x80, 0x0d, 
        0xbc, 0x05, 0x06, 0x13, 
        0x01, 0x00, 0x16, 0x01, 0x02, 0x14, 0x02, 0x00, 
        0x02, 0x33, 0x02, 0x00, 0x01, 0x34, 0x02, 0x00, 
        0x02, 0xc1, 0xa6, 0x31, 0x81, 0xa3, 0xa0, 0x03, 
        0x80, 0x01, 0x01, 0xa2, 0x81, 0x9b, 0x80, 0x02, 
        0x07, 0x80, 0x81, 0x04, 0x00, 0x00, 0x00, 0x01, 
        0x82, 0x04, 0x00, 0x00, 0x00, 0x02, 0xa4, 0x23, 
        0x30, 0x0f, 0x02, 0x01, 0x01, 0x06, 0x04, 0x52, 
        0x01, 0x00, 0x01, 0x30, 0x04, 0x06, 0x02, 0x51, 
        0x01, 0x30, 0x10, 0x02, 0x01, 0x03, 0x06, 0x05, 
        0x28, 0xca, 0x22, 0x02, 0x01, 0x30, 0x04, 0x06, 
        0x02, 0x51, 0x01, 0x88, 0x02, 0x06, 0x00, 0x61, 
        0x60, 0x30, 0x5e, 0x02, 0x01, 0x01, 0xa0, 0x59, 
        0x60, 0x57, 0x80, 0x02, 0x07, 0x80, 0xa1, 0x07, 
        0x06, 0x05, 0x28, 0xca, 0x22, 0x01, 0x01, 0xa2, 
        0x04, 0x06, 0x02, 0x29, 0x02, 0xa3, 0x03, 0x02, 
        0x01, 0x02, 0xa6, 0x04, 0x06, 0x02, 0x29, 0x01, 
        0xa7, 0x03, 0x02, 0x01, 0x01, 0xbe, 0x32, 0x28, 
        0x30, 0x06, 0x02, 0x51, 0x01, 0x02, 0x01, 0x03, 
        0xa0, 0x27, 0xa8, 0x25, 0x80, 0x02, 0x7d, 0x00, 
        0x81, 0x01, 0x14, 0x82, 0x01, 0x14, 0x83, 0x01, 
        0x04, 0xa4, 0x16, 0x80, 0x01, 0x01, 0x81, 0x03, 
        0x05, 0xfb, 0x00, 0x82, 0x0c, 0x03, 0x6e, 0x1d, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x01, 
        0x98
        )
  
  status = socket:send( MMS_INITIATE )
  if not status then
    return nil
  end
  status, recv = socket:receive_bytes(1024)
  stdnse.print_debug(1, "mms_initiate recv: %s", stdnse.tohex(recv) )
  table.insert(output, string.format("mms_initiate send / recv: %s / %s", hex2str( stdnse.tohex(MMS_INITIATE)), hex2str( stdnse.tohex(recv))))

  local MMS_IDENTIFY = string.char(
        0x03, 0x00, 0x00, 0x1b, 0x02, 0xf0, 0x80, 0x01, 
        0x00, 0x01, 0x00, 0x61, 0x0e, 0x30, 0x0c, 0x02, 
        0x01, 0x03, 0xa0, 0x07, 0xa0, 0x05, 0x02, 0x01, 
        0x01, 0x82, 0x00
        )
  
  status = socket:send( MMS_IDENTIFY )
  if not status then
    return nil
  end
  status, recv = socket:receive_bytes(1024)
  stdnse.print_debug(1, "mms_identify recv: %s", stdnse.tohex(recv) )
  table.insert(output, string.format("mms_identify send / recv: %s / %s", hex2str( stdnse.tohex(MMS_IDENTIFY)), hex2str( stdnse.tohex(recv))))

  local parse_err_catch = function()
    stdnse.print_debug(1, "error while parsing answer" )
  end

  local try = nmap.new_try(parse_err_catch)
  
  if ( status and recv ) then
    -- damn! rewrite with bin.unpack!
    table.insert(output, string.format("raw answer: %s", hex2str( stdnse.tohex(recv))))
    local tmp_recv = stdnse.tohex(recv)
    local invokeID_size = tonumber(string.sub(tmp_recv, 47, 48), 16)
    stdnse.print_debug(1, "invokeID_size: %d", invokeID_size )

    local mms_identify_info = string.sub(tmp_recv, 52 + 2*invokeID_size +1)
    local vendor_name_size = tonumber(string.sub(mms_identify_info, 3, 4), 16)
    local vendor_name = string.sub(mms_identify_info, 5, 5 + 2*vendor_name_size -1)
    table.insert(output, string.format("vendor name: %s", hex2str( vendor_name)))

    mms_identify_info = string.sub(mms_identify_info, 5 + 2*vendor_name_size)
    local model_name_size = tonumber(string.sub(mms_identify_info, 3, 4), 16)
    local model_name = string.sub(mms_identify_info, 5, 5 + 2*model_name_size -1)
    table.insert(output, string.format("model name: %s", hex2str( model_name)))

    mms_identify_info = string.sub(mms_identify_info, 5 + 2*model_name_size)
    local revision_size = tonumber(string.sub(mms_identify_info, 3, 4), 16)
    local revision = string.sub(mms_identify_info, 5, 5 + 2*revision_size -1)
    table.insert(output, string.format("revision: %s", hex2str( revision)))
  else
    return nil
  end

  if(#output > 0) then
    port.version.name = "IEC 61850-8-1 MMS"
    nmap.set_port_state(host, port, "open")
    nmap.set_port_version(host, port, "hardmatched")        
    return stdnse.format_output(true, output)
  else
    return nil
  end
end


--[[

    python parsing implementation

    tpkt = struct.unpack('!I', r[:4])
    iso8073 = struct.unpack('!I', '\x00' + r[4:7])
    iso8327 = struct.unpack('!I', r[7:11])
    iso8823 = struct.unpack('!II', '\x00' + r[11:18])
    mms = r[18:]
    a0, a0_packetsize = struct.unpack('!BB', mms[:2])
    a1, a1_packetsize = struct.unpack('!BB', mms[2:4])
    invokeID, invokeID_size = struct.unpack('!BB', mms[4:6])
    a2, a2_packetsize = struct.unpack('!BB', mms[6+invokeID_size:6+invokeID_size+2])
    mms_identify_info = mms[6+invokeID_size+2:]
    vendor_name_size, = struct.unpack('!B', mms_identify_info[1:2])
    vendor_name = ''.join(struct.unpack('!%dc' % vendor_name_size, mms_identify_info[2:2+vendor_name_size]))
    mms_identify_info = mms_identify_info[2+vendor_name_size:]
    model_name_size, = struct.unpack('!B', mms_identify_info[1:2])
    model_name = ''.join(struct.unpack('!%dc' % model_name_size, mms_identify_info[2:2+model_name_size]))
    mms_identify_info = mms_identify_info[2+model_name_size:]
    revision_size, = struct.unpack('!B', mms_identify_info[1:2])
    revision = ''.join(struct.unpack('!%dc' % revision_size, mms_identify_info[2:2+revision_size]))

    print "vendor name: {0}, model name: {1}, revision: {2}".format(vendor_name, model_name, revision)



--]]