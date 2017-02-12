description = [[
Attempts to detect Bradford Networks Network Sentry appliance admin
web interface.
]]

-- @output
-- Nmap scan report for 10.0.0.10
-- Host is up (0.030s latency).
-- PORT     STATE SERVICE
-- 8080/tcp open  http-proxy
-- |_bradford-networks-nac: Bradford Networks NAC admin interface found!




author = "John Babio"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe"}

local http = require "http"
local shortport = require "shortport"
portrule = shortport.http

action = function(host, port)
local resp = "Network Sentry Control Server"

local stat = http.get(host, port, '/')
if stat.status == 200 and http.response_contains(stat, resp) then
    return "Bradford Networks NAC admin interface found!"
  end
end