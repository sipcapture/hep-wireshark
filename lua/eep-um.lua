--
-- Copyright 2016 (C) Giacomo Vacca <giacomo.vacca@gmail.com>
-- Copyright 2016 (C) Federico Cabiddu <federico.cabiddu@gmail.com>
-- Copyright 2017 (C) Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
--
--
-- This file is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 2 of the License, or
-- (at your option) any later version
--
--
-- This file is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

-- Just copy this in your Wireshark plugins folder (either personal or global plugins)


FOUROCTETS = 4
TWOOCTETS = 2
ONEOCTET = 1

eep3_proto = Proto("eep3", "EEP3 Protocol")

eep3_proto.fields = {}
local fds3 = eep3_proto.fields
fds3.eep_id = ProtoField.new("HEP ID", "eep3.id", ftypes.STRING)
fds3.length = ProtoField.new("Length (Bytes)", "eep3.length", ftypes.UINT16)
fds3.protocol_family = ProtoField.new("Protocol family", "eep3.protocol_family", ftypes.STRING)
fds3.protocol_id = ProtoField.new("Protocol ID", "eep3.protocol_id", ftypes.STRING)
fds3.protocol_type = ProtoField.new("Protocol Type", "eep3.protocol_type", ftypes.STRING)
fds3.src_ipv4_address = ProtoField.new("Source IPv4 address", "eep3.src_ipv4_address", ftypes.IPv4)
fds3.dst_ipv4_address = ProtoField.new("Destination IPv4 address", "eep3.dst_ipv4_address", ftypes.IPv4)
fds3.dst_ipv6_address = ProtoField.new("Destination IPv6 address", "eep3.dst_ipv6_address", ftypes.STRING)
fds3.src_ipv6_address = ProtoField.new("Source IPv6 address", "eep3.src_ipv6_address", ftypes.STRING)
fds3.src_port = ProtoField.new("Source port", "eep3.src_port", ftypes.UINT16)
fds3.dst_port = ProtoField.new("Destination port", "eep3.dst_port", ftypes.UINT16)
fds3.timestamp = ProtoField.new("Timestamp", "eep3.timestamp", ftypes.UINT32)
fds3.timestamp_us = ProtoField.new("Timestamp us", "eep3.timestamp_us", ftypes.UINT32)
fds3.capture_id = ProtoField.new("Capture ID", "eep3.capture_id", ftypes.UINT32)
fds3.auth_key = ProtoField.new("Authentication Key", "eep3.auth_key", ftypes.STRING)
fds3.correlation_id = ProtoField.new("Correlation ID", "eep3.correlation_id", ftypes.STRING)
fds3.payload = ProtoField.new("Payload", "eep3.payload", ftypes.STRING)


--------------------------------------------------------------------------------
function get_chunk_type(buffer, offset)
  return tostring(buffer(offset, FOUROCTETS))
end

function get_data(buffer, offset)
  chunk_payload_len = buffer(offset + FOUROCTETS, TWOOCTETS):uint() - (FOUROCTETS + TWOOCTETS)
  chunk_payload_offset = offset + FOUROCTETS + TWOOCTETS
  return buffer(chunk_payload_offset, chunk_payload_len), chunk_payload_offset, chunk_payload_len
end

function add_element(subtree, buffer, offset, len, description, info)
  subtree:add(buffer(offset, len), description .. ": " .. info)
  -- return next offset
  return offset + len
end

function process_proto_family(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)
  if tostring(data) == "02" then
    info = "IPv4"
  elseif tostring(data) == "0a" then
    info = "IPv6"
  else
    info = "Unknown"
  end
  subtree:add(fds3.protocol_family, buffer(offset, len), info)
  return offset + len
end

function process_proto_id(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)
  if tostring(data) == "11" then
    info = "UDP"
  elseif tostring(data) == "06" then
    info = "TCP"
  --else
    -- TODO; add
  end
  subtree:add(fds3.protocol_id, buffer(offset, len), info)
  return offset + len
end

function process_src_ipv4_address(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)  
  info = data:ipv4()
  subtree:add(fds3.src_ipv4_address, buffer(offset, len), info)
  return offset + len
end

function process_dst_ipv4_address(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)  
  info = data:ipv4()
  subtree:add(fds3.dst_ipv4_address, buffer(offset, len), info)
  return offset + len
end

function decompose_ipv6(data)
  local data = tostring(data)
  local i = 1
  local ret = string.sub(data, i, i+3)
  for j=0, 6, 1
  do
    i = i + 4
    ret = ret .. ":" .. string.sub(data, i, i+3)
  end
  ret = string.gsub(ret, ":0000", ":")
  ret = string.gsub(ret, ":000", ":")
  ret = string.gsub(ret, ":00", ":")
  ret = string.gsub(ret, ":0", ":")
  ret = string.gsub(ret, "::::", "::")
  ret = string.gsub(ret, ":::", "::")
  return ret
end

function process_src_ipv6_address(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)
  local info = decompose_ipv6(data)
  subtree:add(fds3.src_ipv6_address, buffer(offset, len), tostring(info))
  return offset + len
end

function process_dst_ipv6_address(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)
  local info = decompose_ipv6(data)
  subtree:add(fds3.dst_ipv6_address, buffer(offset, len), tostring(info))
  return offset + len
end

function process_src_port(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)
  info = data:uint()
  subtree:add(fds3.src_port, buffer(offset, len), info)
  return offset + len
end

function process_dst_port(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)
  info = data:uint()
  subtree:add(fds3.dst_port, buffer(offset, len), info)
  return offset + len
end

function process_timestamp(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)  
  info = data:uint()
  subtree:add(fds3.timestamp, buffer(offset, len), info)
  return offset + len
end

function process_timestamp_us(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)  
  info = data:uint()
  subtree:add(fds3.timestamp_us, buffer(offset, len), info)
  return offset + len
end

function process_protocol_type(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)
    
  if (tostring(data) == "01") then
    info = "SIP"
  elseif (tostring(data) == "05") then -- 5
    info = "JSON/RTCP"
  elseif (tostring(data) == "14") then -- 14
    info = "JSON/webRTC"
  elseif (tostring(data) == "20") then -- 32
    info = "JSON/QOS"
  elseif (tostring(data) == "63") then -- 99
    info = "JSON/QOS"
  elseif (tostring(data) == "64") then -- 100
    info = "LOG"
  else
    info = "Unknown"
-- TODO; add more protocol types
  end
  
  subtree:add(fds3.protocol_type, buffer(offset, len), info)
  next_offset = offset + len
  -- Careful. It must return the protocol type too. Improvable.
  return next_offset, info
end

function process_capture_id(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)  
  info = data:uint()
  subtree:add(fds3.capture_id, buffer(offset, len), info)
  return offset + len
end

function process_auth_key(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)
  info = data:string()
  subtree:add(fds3.auth_key, buffer(offset, len), info)
  return offset + len
end

function process_correlation_id(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)
  info = data:string()
  subtree:add(fds3.correlation_id, buffer(offset, len), info)
  return offset + len
end

function process_payload(buffer, offset, subtree, pinfo, tree, protocol_type)
  data, offset, len = get_data(buffer, offset)
  info = data:string()
  subtree:add(fds3.payload, buffer(offset, len), info)

  if (protocol_type == "SIP") then
    Dissector.get("sip"):call(buffer(offset):tvb(), pinfo, tree)
    pinfo.cols.protocol = "EEP3/SIP"
  elseif ((protocol_type == "JSON") or (protocol_type == "JSON/RTCP") or (protocol_type == "JSON/QOS")) then
    Dissector.get("json"):call(buffer(offset):tvb(), pinfo, tree)
    pinfo.cols.protocol = "EEP3/" .. protocol_type
  elseif (protocol_type == "LOG") then
    pinfo.cols.protocol = "EEP3/" .. protocol_type
  else
    pinfo.cols.protocol = "EEP3"
  end

  next_offset = offset + len
  return next_offset
end

function dissect_eep3(buffer, offset, subtree, pinfo, tree)
  eep_id = buffer(offset, FOUROCTETS):string()
  subtree:add(fds3.eep_id, buffer(offset, FOUROCTETS), eep_id)
  offset = offset + FOUROCTETS
  
  total_len = buffer(offset, TWOOCTETS):uint()
  subtree:add(fds3.length, buffer(offset, TWOOCTETS), total_len)

  offset = offset + TWOOCTETS
  chunk_type = get_chunk_type(buffer, offset)
  
  while (offset < (total_len -1)) do
    if chunk_type == "00000001" then
      offset = process_proto_family(buffer, offset, subtree)
    elseif chunk_type == "00000002" then
      offset = process_proto_id(buffer, offset, subtree)
    elseif chunk_type == "00000003" then
      offset = process_src_ipv4_address(buffer, offset, subtree)
    elseif chunk_type == "00000004" then
      offset = process_dst_ipv4_address(buffer, offset, subtree)
    elseif chunk_type == "00000005" then
      offset = process_src_ipv6_address(buffer, offset, subtree)
    elseif chunk_type == "00000006" then
      offset = process_dst_ipv6_address(buffer, offset, subtree)
    elseif chunk_type == "00000007" then
      offset = process_src_port(buffer, offset, subtree)
    elseif chunk_type == "00000008" then
      offset = process_dst_port(buffer, offset, subtree)
    elseif chunk_type == "00000009" then
      offset = process_timestamp(buffer, offset, subtree)
    elseif chunk_type == "0000000a" then
      offset = process_timestamp_us(buffer, offset, subtree)
    elseif chunk_type == "0000000b" then
      offset, protocol_type = process_protocol_type(buffer, offset, subtree)
    elseif chunk_type == "0000000c" then
      offset = process_capture_id(buffer, offset, subtree)
    elseif chunk_type == "0000000e" then
      offset = process_auth_key(buffer, offset, subtree)
    elseif chunk_type == "0000000f" then
      offset = process_payload(buffer, offset, subtree, pinfo, tree, protocol_type)
    elseif chunk_type == "00000010" then
      -- Compressed payload TODO
    elseif chunk_type == "00000011" then
      offset = process_correlation_id(buffer, offset, subtree)
    elseif chunk_type == "00000012" then
      -- VLAN ID TODO
    elseif chunk_type == "00000013" then
      -- Group ID TODO
    else
      -- something not quite right
    end

    if (offset < (total_len - 1)) then
      chunk_type = get_chunk_type(buffer, offset)
    end
  end -- while
end

function eep3_proto.dissector(buffer, pinfo, tree)
  local subtree = tree:add(eep3_proto, buffer(), "EEP3 Protocol")
  dissect_eep3(buffer, offset, subtree, pinfo, tree)
end


--
tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(9999, eep3_proto)
