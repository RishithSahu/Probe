local real_http = require "http"
local stdnse = require "stdnse"
local nmap = require "nmap"
description = [[Offline HTTP inventory redirect regression tests; HTTP reads are mocked and no packet is sent.]]
author = "Probe"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe"}
prerule = function() return true end

action = function()
  local script = stdnse.get_script_args("inventory-test.script")
  assert(script, "inventory-test.script path is required")
  local passed = 0
  local function run(responses, expected_count, expected_final, expected_stop, arguments)
    local calls = {}
    local mock = {parse_redirect=real_http.parse_redirect}
    mock.get = function(host,port,path,options)
      assert(options.redirect_ok == false, "library redirects must always be disabled")
      assert(options.scheme == "http", "known HTTP scheme must prevent TLS guessing")
      assert(options.truncated_ok == true, "bounded partial pages must remain observable")
      local expected = arguments and tonumber(arguments["http-inventory.header-port"]) == 80 and arguments["http-inventory.forwarded-for"] or nil
      assert((options.header or {})["X-Forwarded-For"] == expected, "forwarding header must match the exact approved endpoint")
      calls[#calls+1] = path
      local response = responses[path]
      assert(response, "unexpected resource requested: "..path)
      return response
    end
    local mock_stdnse = setmetatable({get_script_args=function(name)
      if arguments and arguments[name] then return arguments[name] end
      return stdnse.get_script_args(name)
    end},{__index=stdnse})
    local env = setmetatable({require=function(name) if name == "http" then return mock elseif name == "stdnse" then return mock_stdnse else return require(name) end end}, {__index=_G})
    local chunk,err = loadfile(script,"t",env)
    assert(chunk,err)
    chunk()
    local out = env.action({ip="192.0.2.1"},{number=80,protocol="tcp",state="open",service="http"})
    assert(#calls == expected_count,"incorrect request count: "..#calls)
    if expected_final then assert(out.final_path == expected_final,"incorrect final path") end
    if expected_stop then assert(out.redirect_stop == expected_stop,"incorrect redirect stop") end
    passed = passed+1
  end
  local function redirect(location) return {status=302,header={location=location},body=""} end
  local ok = {status=200,header={server="test"},body="<title>Network status</title>"}
  run({["/"]=redirect("http://192.0.2.1/index.php?p="),["/index.php?p="]=ok},2,"/index.php?p=")
  run({["/"]=redirect("/status"),["/status"]=ok},2,"/status")
  run({["/"]=redirect("http://192.0.2.2/status")},1,"/","redirect changes origin or contains credentials")
  run({["/"]=redirect("http://192.0.2.1:81/status")},1,"/","redirect changes origin or contains credentials")
  run({["/"]=redirect("https://192.0.2.1:80/status")},1,"/","redirect changes origin or contains credentials")
  run({["/"]=redirect("http://user:password@192.0.2.1/status")},1,"/","redirect changes origin or contains credentials")
  run({["/"]=redirect("http://192.0.2.1.example.invalid/status")},1,"/","redirect changes origin or contains credentials")
  run({["/"]=redirect("/status"),["/status"]=redirect("/")},2,"/status","redirect loop")
  run({["/"]=redirect("/one"),["/one"]=redirect("/two"),["/two"]=redirect("/three"),["/three"]=redirect("/four")},4,"/three","three-redirect limit")
  run({["/"]={status=200,header={},body="<a href='/network/'>network</a><a href='/logout'>logout</a><a href='http://192.0.2.2/'>external</a>"},["/network/"]=ok},2,"/network/")
  run({["/"]={status=200,header={},body="<a href='?p=ops'>folder</a><a href='?p=ops&amp;view=network.json'>network metadata</a><a href='?p=ops&amp;view=secrets.txt'>unrelated file</a><a href='?p=ops&amp;delete=network.json'>delete</a>"},["/?p=ops"]=ok,["/?p=ops&view=network.json"]=ok},3,"/?p=ops")
  run({["/"]={status=200,header={},truncated=true,body="<title>Partial network status</title>192.0.2.0/24"}},1,"/")
  run({["/"]=ok},1,"/",nil,{["http-inventory.forwarded-for"]="192.0.2.254",["http-inventory.header-port"]="80"})
  run({["/"]=ok},1,"/",nil,{["http-inventory.forwarded-for"]="192.0.2.254",["http-inventory.header-port"]="81"})
  run({["/"]=redirect("/status"),["/status"]=ok},1,"/",nil,{["http-inventory.max-resources"]="1"})
  return "PASS: "..passed.." offline navigation cases; zero real HTTP requests"
end
