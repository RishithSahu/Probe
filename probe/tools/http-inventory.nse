local http = require "http"
local stdnse = require "stdnse"
local url = require "url"
local nmap = require "nmap"
description = [[Bounded read-only HTTP metadata navigation on the exact same IP, port and scheme. No forms, credentials, mutations or bulk downloads.]]
author = "Probe"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}
portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
  local out = stdnse.output_table()
  local visited, text, resources, content_seen = {}, "", {}, {}
  local requests_made = 0
  local scheme = (port.number == 443 or port.service == "https" or port.service_tunnel == "ssl") and "https" or "http"
  local origin = scheme.."://"..host.ip..":"..port.number
  local queue = {{path="/",depth=0,redirects=0}}
  local budget = tonumber(stdnse.get_script_args("http-inventory.budget-ms")) or 16000
  local deadline = nmap.clock_ms()+math.min(budget,20000)
  local forwarded_for = stdnse.get_script_args("http-inventory.forwarded-for")
  local header_port = tonumber(stdnse.get_script_args("http-inventory.header-port"))
  local max_resources = math.min(12,tonumber(stdnse.get_script_args("http-inventory.max-resources")) or 12)
  local request_headers = {}
  if forwarded_for and header_port == port.number then
    request_headers["X-Forwarded-For"] = forwarded_for
    out.authorised_header_test = true
  end
  local dangerous = {"logout","delete","remove","upload","rename","reboot","reset","shutdown","execute","command","chmod","edit","save","unzip","extract","create","restart","enable","disable"}
  local function safe_path(location, base, navigation)
    if not location or #location > 2048 or location:find("[%c]") then return nil end
    location = location:gsub("&amp;","&")
    local u = url.parse(url.absolute(origin..base,location))
    if u.userinfo or u.host ~= host.ip or (u.scheme and u.scheme ~= scheme) or
       tonumber(u.port or (u.scheme == "https" and 443 or 80)) ~= port.number then return nil end
    local path = u.path or "/"
    local decoded = url.unescape(path):lower()
    if decoded:find("..",1,true) or decoded:find("\\",1,true) or path:sub(1,2)=="//" then return nil end
    if navigation then
      local all = decoded.."?"..url.unescape(u.query or ""):lower()
      for _,word in ipairs(dangerous) do if all:find(word,1,true) then return nil end end
      if u.query then
        if u.query:find(";") then return nil end
        for key,value in u.query:gmatch("([^&=]+)=?([^&]*)") do
          key, value = url.unescape(key):lower(), url.unescape(value):lower()
          if key ~= "p" and key ~= "path" and key ~= "dir" and key ~= "page" and key ~= "view" then return nil end
          if value:find("..",1,true) or value:find("\\",1,true) then return nil end
          if key == "view" and not value:find("net") and not value:find("route") and not value:find("interface") and
             not value:find("topology") and not value:find("inventory") and not value:find("readme") then return nil end
        end
      elseif not decoded:match("/$") and not decoded:match("%.php$") and not decoded:match("%.html?$") and not decoded:match("^/[%w/_%-]*$") then
        local metadata = decoded:find("net") or decoded:find("route") or decoded:find("interface") or decoded:find("topology") or decoded:find("inventory") or decoded:find("readme")
        local extension = decoded:match("%.([a-z]+)$")
        if not metadata or not ({txt=true,json=true,yaml=true,yml=true,csv=true,xml=true,md=true,conf=true})[extension] then return nil end
      end
    end
    return path..(u.query and "?"..u.query or "")
  end
  while #queue > 0 and requests_made < max_resources and nmap.clock_ms() < deadline-500 do
    local item = table.remove(queue,1)
    local path = item.path
    if not visited[path] then
      visited[path] = true
      requests_made = requests_made+1
      local resp = http.get(host,port,path,{redirect_ok=false,scheme=scheme,header=request_headers,max_body_size=131072,truncated_ok=true,
                                          timeout=math.min(5000,math.max(500,deadline-nmap.clock_ms()-300))})
      if not resp or not resp.status then
        out.observation_error = "one or more resources gave no HTTP response"
      else
        local body = resp.body or ""
        local resource = stdnse.output_table()
        resource.path,resource.status,resource.truncated = path,resp.status,resp.truncated or false
        resource.title = body:match("<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]*)")
        resource.server = (resp.header or {})["server"]
        resource.location = (resp.header or {})["location"]
        resource.links,resource.navigation_links = {},{}
        local plain = body:gsub("<[Ss][Cc][Rr][Ii][Pp][Tt].-</[Ss][Cc][Rr][Ii][Pp][Tt]>"," "):gsub("<[Ss][Tt][Yy][Ll][Ee].-</[Ss][Tt][Yy][Ll][Ee]>"," "):gsub("<[^>]+>"," "):gsub("%s+"," ")
        resource.page_text = plain:sub(1,8192)
        out.initial_status = out.initial_status or resp.status
        out.status,out.title,out.server,out.final_path = resp.status,resource.title,resource.server,path
        text = text.."\n"..body
        for k,v in pairs(resp.header or {}) do text = text.."\n"..k..": "..tostring(v) end
        resources[#resources+1] = resource
        local is_redirect = tostring(resp.status):match("^30[12378]$") and resource.location
        if is_redirect then
          local next_path = safe_path(resource.location,path,false)
          if not next_path then
            out.location_not_followed,out.redirect_stop = resource.location,"redirect changes origin or contains credentials"
          elseif visited[next_path] then out.redirect_stop = "redirect loop"
          elseif item.redirects >= 3 then out.redirect_stop = "three-redirect limit"
          else table.insert(queue,1,{path=next_path,depth=item.depth,redirects=item.redirects+1}) end
        elseif resp.status == 200 and not content_seen[plain] then
          content_seen[plain] = true
          for link in body:gmatch("[Hh][Rr][Ee][Ff]%s*=%s*['\"]([^'\"]+)['\"]") do
            if #resource.links < 64 then resource.links[#resource.links+1] = link end
            local next_path = safe_path(link,path,true)
            if next_path and next_path ~= path and #resource.navigation_links < 24 then
              resource.navigation_links[#resource.navigation_links+1] = next_path
              if item.depth < 2 and not visited[next_path] and #queue < 32 then
                local follow = {path=next_path,depth=item.depth+1,redirects=0}
                if next_path:find("[?&]view=") then table.insert(queue,1,follow) else queue[#queue+1] = follow end
              end
            end
          end
        end
      end
    end
  end
  out.resources = resources
  out.requests_made = requests_made
  out.max_requests = max_resources
  out.navigation_incomplete = #queue > 0
  out.remaining_resources = #queue
  out.remaining_paths = {}
  for i,item in ipairs(queue) do if i <= 24 then out.remaining_paths[#out.remaining_paths+1] = item.path end end
  local seen,addresses,prefixes = {},{},{}
  for value in text:gmatch("%d+%.%d+%.%d+%.%d+/%d+") do
    if not seen[value] then prefixes[#prefixes+1]=value; seen[value]=true end
  end
  for value in text:gmatch("%d+%.%d+%.%d+%.%d+") do
    if not seen[value] then addresses[#addresses+1]=value; seen[value]=true end
  end
  out.reported_addresses,out.reported_prefixes = addresses,prefixes
  out.interpretation = "Service metadata only; references do not establish reachability, subnet membership, or authorisation"
  return out
end
