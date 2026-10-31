local nmap = require "nmap"
local stdnse = require "stdnse"
description = [[Connect and read an initial TCP banner without sending application data or credentials.]]
author = "Probe"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}
portrule = function(host,port) return port.protocol == "tcp" and port.state == "open" end
action = function(host,port)
  local socket = nmap.new_socket()
  socket:set_timeout(3000)
  local ok,err = socket:connect(host.ip,port.number,"tcp")
  if not ok then socket:close(); return nil end
  local got,data = socket:receive_bytes(1)
  socket:close()
  if not got then return nil end
  local out = stdnse.output_table()
  out.banner = data:sub(1,4096)
  out.application_bytes_sent = 0
  return out
end
