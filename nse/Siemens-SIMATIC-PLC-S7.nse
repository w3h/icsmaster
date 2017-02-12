local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local strbuf = require "strbuf"


description = [[
Checks for SCADA Siemens <code>Simatic S7</code> devices.

The higher the verbosity or debug level, the more disallowed entries are shown.
]]

---
--@output
-- 80/tcp  open   http    syn-ack
-- |_Siemens-Simatic-S7: SIMATIC 300 (MPI2)/CPU 315-2 PN/DP



author = "Jose Ramon Palanco, drainware"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.http
local last_len = 0


local function verify_version(body, output)
	local version = nil
	if string.find (body, "/S7Web.css") then
	  version = body:match("<td valign=\"top\" class=\"Header_Title_Description\">(.-)</td>")
	  version = version:gsub("&nbsp;", " ")
		if version == nil then 
			version = "Unknown version"
		end	
	  output = output .. version
	  return true
	 elseif string.find (body, "snCplugPresent") then
	  version = body:match("Siemens, (.-)&nbsp;!!!")
	  version = version:gsub("&nbsp;", " ")
		if version == nil then 
			version = "Unknown version"
		end	
	  output = output .. version
	  return true

	else
	  return nil
	end 
end

action = function(host, port)
    local verified, noun 
	local answer1 = http.get(host, port, "/Portal/Portal.mwsl" )
	local answer2 = http.get(host, port, "/docs/cplugError.html/" )

	if answer1.status ~= 200 and answer2.status ~= 200 then
		return nil
	end

	if answer1.status == 200 then
  		answer = answer1
	elseif answer2.status == 200 then
		answer = answer2
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