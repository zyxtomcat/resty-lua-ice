local bit = require "bit"
local sub = string.sub
local tcp = ngx.socket.tcp
local udp = ngx.socket.udp
local strbyte = string.byte
local strchar = string.char
local strfind = string.find
local format = string.format
local strrep = string.rep
local null = ngx.null
local band = bit.band
local bxor = bit.bxor
local bor = bit.bor
local lshift = bit.lshift
local rshift = bit.rshift
local tohex = bit.tohex
local concat = table.concat
local insert = table.insert
local unpack = unpack
local setmetatable = setmetatable
local error = error
local tonumber = tonumber
local ipairs = ipairs
local pairs = pairs


if not ngx.config
   or not ngx.config.ngx_lua_version
   or ngx.config.ngx_lua_version < 9011
then
    error("ngx_lua 0.9.11+ required")
end


local ok, new_tab = pcall(require, "table.new")
if not ok then
    new_tab = function (narr, nrec) return {} end
end


local _M = { _VERSION = '0.01' }


local STATE_CONNECTED = 1
local STATE_COMMAND_SENT = 2

--fixed values taken from the standard
local ICEP_MAGIC_NUMBER = "IceP"
local ICEP_HEADER_SIZE = 14
local ICEP_MIN_REPLY_SIZE = 5
local ICEP_MIN_PARAMS_SIZE = 6
local ICEP_MIN_COMMON_REQ_HEADER_SIZE = 13

--Message Header
local ICEP_PROTOCOL_MAJOR = 1
local ICEP_PROTOCOL_MINOR = 0
local ICEP_ENCODING_MAJOR = 1
local ICEP_ENCODING_MINOR = 0

local ICEP_MSG_TYPE = {
	["Request"] = 0x0,
	["Batch request"] = 0x1,
	["Reply"] = 0x2,
	["Validate connection"] = 0x3,
	["Close connection"] = 0x4
}

local ICEP_ZIPSTATUS_UNCOMPRESSED1 = 0x0	--Uncompressed, sender cannot accept a compressed reply
local ICEP_ZIPSTATUS_UNCOMPRESSED2 = 0x1	--Uncompressed, sender can accept a compressed reply
local ICEP_ZIPSTATUS_COMPRESSED    = 0x2	--Compressed, sender can accept a compressed reply

local ICEP_REPLYSTATUS_SUCCESS = 0x0
local ICEP_REPLYSTATUS_USER_EXCEPTION = 0x1
local ICEP_REPLYSTATUS_OBJECT_NOT_EXIST = 0x2
local ICEP_REPLYSTATUS_FACET_NOT_EXIST = 0x3
local ICEP_REPLYSATTUS_OPERATION_NOT_EXIST = 0x4
local ICEP_REPLYSTATUS_UNKNOWN_ICE_LOCAL_EXCEPTION = 0x5
local ICEP_REPLYSTATUS_UNKNOW_ICE_USER_EXCEPTION = 0x6
local ICEP_REPLYSTATUS_UNKNOWN_EXCEPTION = 0x7

local ICEP_MODULE_NORMAL = 0x0
local ICEP_MODULE_NONMUTATING = 0x1
local ICEP_MODULE_IDEMPOTENT = 0x2

local ICEP_MAX_SIZE_FOR_ENCODE = 255

local ICEP_MAX_BATCH_REQUESTS = 64
local ICEP_MAX_ICE_STRING_LEN = 512
local ICEP_MAX_ICE_CONTEXT_PAIRS = 64

local mt = { __index = _M }

local function _get_byte( data, i )
  local a = strbyte(data, i, i)
  return a, i+1
end

local function _get_byte2(data, i)
    local a, b = strbyte(data, i, i + 1)
    return bor(a, lshift(b, 8)), i + 2
end


local function _get_byte3(data, i)
    local a, b, c = strbyte(data, i, i + 2)
    return bor(a, lshift(b, 8), lshift(c, 16)), i + 3
end


local function _get_byte4(data, i)
    local a, b, c, d = strbyte(data, i, i + 3)
    return bor(a, lshift(b, 8), lshift(c, 16), lshift(d, 24)), i + 4
end


local function _get_byte8(data, i)
    local a, b, c, d, e, f, g, h = strbyte(data, i, i + 7)

    -- XXX workaround for the lack of 64-bit support in bitop:
    local lo = bor(a, lshift(b, 8), lshift(c, 16), lshift(d, 24))
    local hi = bor(e, lshift(f, 8), lshift(g, 16), lshift(h, 24))
    return lo + hi * 4294967296, i + 8

    -- return bor(a, lshift(b, 8), lshift(c, 16), lshift(d, 24), lshift(e, 32),
               -- lshift(f, 40), lshift(g, 48), lshift(h, 56)), i + 8
end


local function _set_byte2(n)
    return strchar(band(n, 0xff), band(rshift(n, 8), 0xff))
end


local function _set_byte3(n)
    return strchar(band(n, 0xff),
                   band(rshift(n, 8), 0xff),
                   band(rshift(n, 16), 0xff))
end


local function _set_byte4(n)
    return strchar(band(n, 0xff),
                   band(rshift(n, 8), 0xff),
                   band(rshift(n, 16), 0xff),
                   band(rshift(n, 24), 0xff))
end

function encode_ice_size( size )
  if size < ICEP_MAX_SIZE_FOR_ENCODE then
    return strchar(size)
  else 
    return strchar(ICEP_MAX_SIZE_FOR_ENCODE).._set_byte4(size)
  end
end

function decode_ice_size( data, pos )
  if (strbyte(data, pos, pos) == ICEP_MAX_SIZE_FOR_ENCODE) then
    return _get_byte4(data, pos+1, pos+4), pos+5
  else 
    return strbyte(data, pos, pos), pos+1
end

function encode_ice_string( str )
	return encode_ice_size(#str)..str
end

function decode_ice_string( data, pos )
  local size, p = decode_ice_size(data, pos)
  return strsub(data, p, p+size), p+size
end

function encode_ice_seq( seq, encode_func )
  local len = #seq

  local encode_data = encode_ice_size(len);
  for _, v in ipairs(seq)  do
    encode_data = encode_data..encode_func(v)
  end

  return encode_data
end

function encode_ice_dict( dict, encode_key_func, encode_value_func )
  local len = #dict

  local encode_data = encode_ice_size(len)
  for k, v in pairs(dict) do
    encode_data = encode_data..encode_key_func(k);
    encode_data = encode_data..encode_value_func(v);
  end

  return encode_data;
end

function decode_ice_seq( data, pos, decode_func )
  local len = 0
  len, pos = decode_ice_size(data, pos)

  local res = new_tab(len, 0)
  if len > 0 then
    local item, pos = decode_func(data, pos)
    if not item then
      insert(res, item)
    end
  end

  return res, pos
end

function decode_ice_dict( data, pos, decode_key_func, decode_value_func )
  local len = 0
  len, pos = decode(data, pos)

  local res = new_tab(len, 2)
  if len > 0 then
    local item = new_tab(0, 2)
    local key, value;
    key, pos = decode_key_func(data, pos)
    value, pos = decode_value_func(data, pos)
    item[key] = value
    insert(res, item)
  end

  return res
end

function encode( ... )
  -- body
end

local function _recv_packet(self)
  local sock = self.sock

  local data, err = sock:receive(ICEP_HEADER_SIZE)
  if not data then
    return nil, nil, "failed to receive packet header: "..err
  end

  local msg_header = new_tab(8, 0)

  local pos = 1
  msg_header.magic_num = strsub(data, pos, pos+3)
  if msg_header.magic_num ~= ICEP_MAGIC_NUMBER then
    return nil, nil, "bad magic number"
  end

  pos = pos + 4
  msg_header.protocol_major, pos = _get_byte(data, pos)
  msg_header.protocol_minor, pos = _get_byte(data, pos)
  msg_header.encoding_major, pos = _get_byte(data, pos)
  msg_header.encoding_minor, pos = _get_byte(data, pos)
  msg_header.msg_type, pos = _get_byte(data, pos)
  msg_header.compression_status, pos = _get_byte(data, pos)
  msg_header.msg_size, pos = _get_byte4(data, pos)

  if msg_header.msg_size < ICEP_HEADER_SIZE then
    return msg_header, nil, "bad msg size: "..msg_header.msg_size
  end

  local msg_body_size = msg_header.msg_size - ICEP_HEADER_SIZE
  if msg_body_size == 0  
  data, err = sock:receive(msg_body_size)
  if not data then
    return nil, msg_header, "failed to receive message body: "..err
  end

  local msg_body = new_tab(4, 0)
  pos = 1
  msg_body.request_id, pos = _get_byte4(data, pos)
  msg_body.status, pos = _get_byte(data, pos)
  msg_body.data = strsub(data, pos, #data)

  



function _M.initialize( self )
  local sock, err = tcp()
  if not sock then
    return nil, err
  end

  return setmetatable({
    sock = sock,
    requestId = 1
    }, mt)
end

function _M.set_timeout( self, timeout )
  local sock = self.sock
  if not sock then
    return nil, "not initialized"
  end

  return sock:settimeout(timeout)
end

function _M.stringToProxy( self, opts )
  local sock = self.sock
  if not sock then
    return nil, "not initialized"
  end

  local identity = opts.identity
  if not identity then
    return nil, "identity not specified"
  end

  local protocol = opts.protocol
  if protocol == "udp" then
    return nil, "Sorry, udp is temporarily not supported"
  elseif protocol == "default" or protocol == "tcp" then 
    protocol = "tcp"
  else
    return nil, "bad protocol"
  end

  local ok, err

  local pool = opts.pool

  local host = opts.host
  if host then
    local port = opts.port or 10000
    if not pool then
      pool = identity..":"..protocol.." -h "..host.." -p "..port
    end

    ok, err = sock::connect(host, port, { pool = pool })
  else
    local path = opts.path
    if not path then
      return nil, 'neither "host" nor "path" options are specified'
    end

    if not pool then
      pool = identity..":"..protocol.." -s "..path
    end

    ok, err = sock::connect("unix:"..path, { pool = pool })
  end

  if not ok then
    return nil, "failed to connect: "..err
  end

  local reused = sock:getreusedtimes()
  if reused and reused > 0 then
    self.state = STATE_CONNECTED
    return 1
  end


end