local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local strbuf = require "strbuf"


description = [[
Checks for SCADA Siemens <code>SIMATIC S7-</code> devices.

The higher the verbosity or debug level, the more disallowed entries are shown.
]]

---
--@output
-- 80/tcp  open   http    syn-ack
-- |_SIEMENS-HMI-miniweb: Not implemented verify_version



author = "Jose Ramon Palanco, drainware"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.http
local last_len = 0


local function verify_version(body, output)
	local version = nil
	if string.find (body, "ad_header_form_sprachauswahl") then
	  version = body:match("")
		if version == nil then 
			version = "Not implemented verify_version"
		end	
	  output = output .. version
	  return true
	else
	  return nil
	end 
end

action = function(host, port)
        local verified, noun 
	local answer = http.get(host, port, "/CSS/Miniweb.css" )

	if answer.status ~= 200 then
		return nil
	end

	local v_level = nmap.verbosity() + (nmap.debugging()*2)
	local detail = 15
	local output = strbuf.new()
	

	verified = verify_version(answer.body, output)
	

	if verified == nil then 
		return
	end

	-- verbose/debug mode, print 50 entries
	if v_level > 1 and v_level < 5 then 
		detail = 40 
	-- double debug mode, print everything
	elseif v_level >= 5 then
		detail = verified
	end


    return output
end