local bit = require "bit"
local sub = string.sub
local tcp = ngx.socket.tcp
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
local unpack = unpack
local setmetatable = setmetatable
local error = error
local tonumber = tonumber

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


local ICEP_MAX_BATCH_REQUESTS = 64
local ICEP_MAX_ICE_STRING_LEN = 512
local ICEP_MAX_ICE_CONTEXT_PAIRS = 64

local mt = { __index = _M }

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

function encode_ice_string( str )
	local len = #str
	if len > ICEP_MAX_BATCH_REQUESTS 
end