local http = require "http"
local stdnse = require "stdnse"
description = [[Read one HTTP root resource, without redirects, and report network references as unverified metadata.]]
author = "Probe"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}
portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end
action = function(host, port)
  local resp = http.get(host, port, "/", {redirect_ok=false, max_body_size=32768, timeout=4000})
  if not resp or not resp.status then return nil end
  local out = stdnse.output_table()
  out.status = resp.status
  out.title = (resp.body or ""):match("<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]*)")
  out.server = (resp.header or {})["server"]
  out.location_not_followed = (resp.header or {})["location"]
  local text = (resp.body or "")
  for k,v in pairs(resp.header or {}) do text = text .. "\n" .. k .. ": " .. tostring(v) end
  local seen, addresses, prefixes = {}, {}, {}
  for value in text:gmatch("%d+%.%d+%.%d+%.%d+/%d+") do
    if not seen[value] then prefixes[#prefixes+1] = value; seen[value] = true end
  end
  for value in text:gmatch("%d+%.%d+%.%d+%.%d+") do
    if not seen[value] then addresses[#addresses+1] = value; seen[value] = true end
  end
  out.reported_addresses = addresses
  out.reported_prefixes = prefixes
  out.interpretation = "Service metadata only; references do not establish reachability, subnet membership, or authorisation"
  return out
end
