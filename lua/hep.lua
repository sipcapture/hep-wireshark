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

hep_proto = Proto("hep", "HEP Protocol")
hep2_proto = Proto("hep2", "HEP2 Protocol")
hep3_proto = Proto("hep3", "HEP3 Protocol")

hep_proto.fields = {}
local fds = hep_proto.fields
fds.version = ProtoField.new("Version", "hep.version", ftypes.UINT8)

hep2_proto.fields = {}
local fds2 = hep2_proto.fields
fds2.version = ProtoField.new("Version", "hep2.version", ftypes.UINT8)
fds2.hep_packet_size = ProtoField.new("HEP Packet Size (Bytes)", "hep2.hep_packet_size", ftypes.UINT8)
fds2.ip_family = ProtoField.new("IP family", "hep2.ip_family", ftypes.STRING)
fds2.transport_layer_protocol = ProtoField.new("Ingested Transport Protocol", "hep2.transport_layer_protocol", ftypes.STRING)
fds2.source_port = ProtoField.new("Source port", "hep2.source_port", ftypes.UINT16)
fds2.destination_port = ProtoField.new("Destination port", "hep2.destination_port", ftypes.UINT16)
fds2.source_ip_address = ProtoField.new("Source IPv4 address", "hep2.source_ip_address", ftypes.IPv4)
fds2.destination_ip_address = ProtoField.new("Destination IPv4 address", "hep2.destination_ip_address", ftypes.IPv4)
fds2.timestamp_unix = ProtoField.new("Unix Timestamp (LE)", "hep2.timestamp_unix", ftypes.UINT32)
fds2.timestamp_microsec = ProtoField.new("Timestamp µs (LE)", "hep2.timestamp_microsec", ftypes.UINT32)
fds2.capture_node_id = ProtoField.new("Capture Node ID (LE)", "hep2.capture_node_id", ftypes.UINT16)
fds2.payload = ProtoField.new("Encapsulated Payload", "hep3.payload", ftypes.STRING)

hep3_proto.fields = {}
local fds3 = hep3_proto.fields
fds3.hep_version = ProtoField.new("HEP Version", "hep3.version", ftypes.STRING)
fds3.hep_packet_size = ProtoField.new("HEP Packet Size (Bytes)", "hep3.hep_packet_size", ftypes.UINT16)
fds3.ip_family = ProtoField.new("IP family", "hep3.ip_family", ftypes.STRING)
fds3.transport_layer_protocol = ProtoField.new("Ingested Transport Protocol", "hep3.transport_layer_protocol", ftypes.STRING)
fds3.application_protocol = ProtoField.new("Application Protocol", "hep3.application_protocol", ftypes.STRING)
fds3.source_ipv4_address = ProtoField.new("Source IPv4 address", "hep3.source_ipv4_address", ftypes.IPv4)
fds3.destination_ipv4_address = ProtoField.new("Destination IPv4 address", "hep3.destination_ipv4_address", ftypes.IPv4)
fds3.source_ipv6_address = ProtoField.new("Source IPv6 address", "hep3.source_ipv6_address", ftypes.IPv6)
fds3.destination_ipv6_address = ProtoField.new("Destination IPv6 address", "hep3.destination_ipv6_address", ftypes.IPv6)
fds3.vlan_id = ProtoField.new("VLAN ID", "hep3.vlan_id", ftypes.UINT16)
fds3.group_id = ProtoField.new("Group ID", "hep3.group_id", ftypes.STRING)
fds3.source_mac = ProtoField.new("Source MAC address", "hep3.source_mac", ftypes.STRING) -- .ETHER
fds3.destination_mac = ProtoField.new("Destination MAC address", "hep3.destination_mac", ftypes.STRING) -- .ETHER
fds3.ethernet_type = ProtoField.new("Ethernet Type", "hep3.ethernet_type", ftypes.UINT16)
fds3.ip_TOS = ProtoField.new("IP TOS", "hep3.ip_TOS", ftypes.UINT8)
fds3.tcp_flags = ProtoField.new("TCP Flags", "hep3.tcp_flags", ftypes.UINT8)
fds3.source_port = ProtoField.new("Source port", "hep3.source_port", ftypes.UINT16)
fds3.destination_port = ProtoField.new("Destination port", "hep3.destination_port", ftypes.UINT16)
fds3.mos = ProtoField.new("MOS", "hep3.mos", ftypes.UINT16)
fds3.timestamp_unix = ProtoField.new("Unix Timestamp", "hep3.timestamp_unix", ftypes.UINT32)
fds3.timestamp_microsec = ProtoField.new("Timestamp µs", "hep3.timestamp_microsec", ftypes.UINT32)
fds3.capture_node_id = ProtoField.new("Capture Node ID", "hep3.capture_node_id", ftypes.UINT32)
fds3.auth_key = ProtoField.new("Authentication Key", "hep3.auth_key", ftypes.STRING)
fds3.correlation_id = ProtoField.new("Correlation ID", "hep3.correlation_id", ftypes.STRING)
fds3.payload = ProtoField.new("Encapsulated Payload", "hep3.payload", ftypes.STRING)
fds3.vendor_id = ProtoField.new("Vendor ID", "hep3.vendor_id", ftypes.UINT16)

--------------------------------------------------------------------------------
function get_chunk_data(buffer, offset)
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

function get_ip_family(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)
  if tostring(data) == "02" then
    info = "IPv4"
  elseif tostring(data) == "0a" then
    info = "IPv6"
  else
    info = "Unknown IP Family"
  end
  subtree:add(fds3.ip_family, buffer(offset, len), info)
  return offset + len
end

function get_transport_proto_id(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)
  if tostring(data) == "11" then
    info = "UDP"
  elseif tostring(data) == "06" then
    info = "TCP"
  elseif tostring(data) == "84" then
    info = "SCTP"
  --else
    -- TODO; add
  end
  subtree:add(fds3.transport_layer_protocol, buffer(offset, len), info)
  return offset + len
end

function get_source_ipv4_address(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)  
  info = data:ipv4()
  subtree:add(fds3.source_ipv4_address, buffer(offset, len), info)
  return offset + len
end

function get_destination_ipv4_address(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)  
  info = data:ipv4()
  subtree:add(fds3.destination_ipv4_address, buffer(offset, len), info)
  return offset + len
end

-- function decompose_ipv6(data)
--   -- this function may only be useful in legacy versions of Wireshark
--   local data = tostring(data)
--   local i = 1
--   local ret = string.sub(data, i, i+3)
--   for j=0, 6, 1
--   do
--     i = i + 4
--     ret = ret .. ":" .. string.sub(data, i, i+3)
--   end
--   ret = string.gsub(ret, ":0000", ":")
--   ret = string.gsub(ret, ":000", ":")
--   ret = string.gsub(ret, ":00", ":")
--   ret = string.gsub(ret, ":0", ":")
--   ret = string.gsub(ret, "::::", "::")
--   ret = string.gsub(ret, ":::", "::")
--   return ret
-- end

function get_source_ipv6_address(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)
  -- local info = decompose_ipv6(data)
  info = data:ipv6()
  subtree:add(fds3.source_ipv6_address, buffer(offset, len), info)
  return offset + len
end

function get_destination_ipv6_address(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)
  -- local info = decompose_ipv6(data)
  info = data:ipv6()
  subtree:add(fds3.destination_ipv6_address, buffer(offset, len), info)
  return offset + len
end

function get_source_port(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)
  info = data:uint()
  subtree:add(fds3.source_port, buffer(offset, len), info)
  return offset + len
end

function get_destination_port(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)
  info = data:uint()
  subtree:add(fds3.destination_port, buffer(offset, len), info)
  return offset + len
end

function get_mos(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)
  info = data:uint()
  subtree:add(fds3.mos, buffer(offset, len), info)
  return offset + len
end

function get_timestamp(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)  
  info = data:uint()
  subtree:add(fds3.timestamp_unix, buffer(offset, len), info)
  return offset + len
end

function get_timestamp_microsec(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)  
  info = data:uint()
  subtree:add(fds3.timestamp_microsec, buffer(offset, len), info)
  return offset + len
end

function get_vlan_id(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)  
  info = data:uint()
  subtree:add(fds3.vlan_id, buffer(offset, len), info)
  return offset + len
end

function get_group_id(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)  
  info = data:uint()
  subtree:add(fds3.group_id, buffer(offset, len), info)
  return offset + len
end

function get_source_mac(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)  
  info = data:string() -- :ether() also avail, but range must be 6 bytes
  subtree:add(fds3.source_mac, buffer(offset, len), info)
  return offset + len
end

function get_destination_mac(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)  
  info = data:string() -- :ether() also avail, but range must be 6 bytes
  subtree:add(fds3.destination_mac, buffer(offset, len), info)
  return offset + len
end

function get_ethernet_type(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)  
  info = data:uint()
  subtree:add(fds3.ethernet_type, buffer(offset, len), info)
  return offset + len
end

function get_tcp_flags(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)  
  info = data:uint()
  subtree:add(fds3.tcp_flags, buffer(offset, len), info)
  return offset + len
end

function get_ip_TOS(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)  
  info = data:uint()
  subtree:add(fds3.ip_TOS, buffer(offset, len), info)
  return offset + len
end


function process_vendor_id(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)  
  info = data:uint()
  subtree:add(fds3.vendor_id, buffer(offset, len), info)
  return offset + len
end

function get_application_protocol(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)
    
  if (tostring(data) == "01") then
    info = "SIP"
  elseif (tostring(data) == "02") then -- 2
    info = "XMPP"
  elseif (tostring(data) == "03") then -- 3
    info = "SDP"
  elseif (tostring(data) == "04") then -- 4
    info = "RTP"
  elseif (tostring(data) == "05") then -- 5
    info = "JSON/RTCP"
  elseif (tostring(data) == "06") then -- 6
    info = "MGCP"
  elseif (tostring(data) == "07") then -- 7
    info = "MEGACO" --H.248
  elseif (tostring(data) == "08") then -- 8
    info = "M2UA"
  elseif (tostring(data) == "09") then -- 9
    info = "M3UA" -- SS7/SIGTRAN
  elseif (tostring(data) == "0a") then -- 10
    info = "IAX"
  elseif (tostring(data) == "0b") then -- 11
    info = "H3222"
  elseif (tostring(data) == "0c") then -- 12
    info = "H321"
  elseif (tostring(data) == "0d") then -- 13
    info = "M2PA"
  elseif (tostring(data) == "14") then -- 14
    info = "JSON/webRTC"
  elseif (tostring(data) == "20") then -- 32
    info = "JSON/QOS/32"
  elseif (tostring(data) == "22") then -- 34
    info = "JSON/QOS/34"
  elseif (tostring(data) == "23") then -- 35
    info = "MOS"
  elseif (tostring(data) == "32") then -- 50
    info = "JSON/SIP"
  elseif (tostring(data) == "33") then -- 51
    info = "RESERVED"
  elseif (tostring(data) == "34") then -- 52
    info = "RESERVED"
  elseif (tostring(data) == "35") then -- 53
    info = "JSON/DNS"
  elseif (tostring(data) == "36") then -- 54
    info = "JSON/M3UA(ISUP)"
  elseif (tostring(data) == "37") then -- 55
    info = "JSON/RTSP"
  elseif (tostring(data) == "38") then -- 56
    info = "JSON/DIAMETER"
  elseif (tostring(data) == "39") then -- 57
    info = "JSON/GSM_MAP"
  elseif (tostring(data) == "63") then -- 99
    info = "JSON/QOS/99"
  elseif (tostring(data) == "64") then -- 100
    info = "LOG" -- for ingest into Loki
  else
    info = "Unknown Application Protocol"
-- TODO; add more protocol types
  end
  
  subtree:add(fds3.application_protocol, buffer(offset, len), info)
  next_offset = offset + len
  -- Careful. It must return the protocol type too. Improvable.
  return next_offset, info
end

function get_capture_node_id(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)  
  info = data:uint()
  subtree:add(fds3.capture_node_id, buffer(offset, len), info)
  return offset + len
end

function get_auth_key(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)
  info = data:string()
  subtree:add(fds3.auth_key, buffer(offset, len), info)
  return offset + len
end

function get_correlation_id(buffer, offset, subtree)
  data, offset, len = get_data(buffer, offset)
  info = data:string()
  subtree:add(fds3.correlation_id, buffer(offset, len), info)
  return offset + len
end

function skip_unknown_chunk(buffer, offset)
  data, offset, len = get_data(buffer, offset)
  return offset + len
end

function determine_payload_content(buffer, offset, subtree, pinfo, tree, application_protocol)
  data, offset, len = get_data(buffer, offset)
  info = data:string()
  subtree:add(fds3.payload, buffer(offset, len), info)

  if (application_protocol == "SIP") then
    Dissector.get("sip"):call(buffer(offset):tvb(), pinfo, tree)
    pinfo.cols.protocol = "HEP3/SIP"
  elseif ((application_protocol == "JSON") or (application_protocol == "JSON/RTCP") or (application_protocol == "JSON/QOS/32") or (application_protocol == "JSON/QOS/99") or (application_protocol == "MOS") or (application_protocol == "JSON/QOS/34")) then
    Dissector.get("json"):call(buffer(offset):tvb(), pinfo, tree)
    pinfo.cols.protocol = "HEP3/" .. application_protocol
  elseif (application_protocol == "LOG") then
    pinfo.cols.protocol = "HEP3/" .. application_protocol
  elseif (application_protocol == "M2UA") then
    Dissector.get("m2ua"):call(buffer(offset):tvb(), pinfo, tree)
    pinfo.cols.protocol = "HEP3/M2UA"
  elseif (application_protocol == "RTP") then
    Dissector.get("rtp"):call(buffer(offset):tvb(), pinfo, tree)
    pinfo.cols.protocol = "HEP3/RTP"
  elseif (application_protocol == "M2PA") then
    Dissector.get("m2pa"):call(buffer(offset):tvb(), pinfo, tree)
    pinfo.cols.protocol = "HEP3/M2PA"
  else
    pinfo.cols.protocol = "HEP3"
  end

  next_offset = offset + len
  return next_offset
end

function dissect_hep2(buffer, offset, subtree, pinfo, tree)
  version = buffer(offset, ONEOCTET):uint()
  subtree:add(fds2.version, buffer(offset, ONEOCTET), version)

  offset = ONEOCTET
  
  total_len = buffer(offset, ONEOCTET):uint()
  subtree:add(fds2.hep_packet_size, buffer(offset, ONEOCTET), total_len)

  offset = offset + ONEOCTET

  ip_family_buffer = buffer(offset, ONEOCTET)
  
  if (tostring(ip_family_buffer) == "02") then
    ip_family = "IPv4"
  elseif (tostring(ip_family_buffer) == "10") then
    ip_family = "IPv6"
  else
    ip_family = "Unknown IP Family"
  end
  
  subtree:add(fds2.ip_family, buffer(offset, ONEOCTET), ip_family)

  offset = offset + ONEOCTET

  transport_layer_protocol_id_buffer = buffer(offset, ONEOCTET)
  
  if (tostring(transport_layer_protocol_id_buffer) == "11") then
    transport_layer_protocol = "UDP"
  elseif (tostring(transport_layer_protocol_id_buffer) == "06") then
    transport_layer_protocol = "TCP"
  -- elseif (tostring(transport_layer_protocol_id_buffer) == "01") then
    -- Fixes https://github.com/sipcapture/hep-wireshark/issues/4
    -- transport_layer_protocol = "UDP (incorrect id)" --issue capture uses UDP
  else
    transport_layer_protocol = "Unidentified Transport"
    -- TODO: Add remaining
  end

  subtree:add(fds2.transport_layer_protocol, buffer(offset, ONEOCTET), transport_layer_protocol)
  offset = offset + ONEOCTET

  source_port = buffer(offset, TWOOCTETS):uint()
  subtree:add(fds2.source_port, buffer(offset, TWOOCTETS), source_port)
  offset = offset + TWOOCTETS

  destination_port = buffer(offset, TWOOCTETS):uint()
  subtree:add(fds2.destination_port, buffer(offset, TWOOCTETS), destination_port)
  offset = offset + TWOOCTETS

  ip = buffer(offset, FOUROCTETS):ipv4()
  subtree:add(fds2.source_ip_address, buffer(offset, FOUROCTETS), ip)
  offset = offset + FOUROCTETS

  ip = buffer(offset, FOUROCTETS):ipv4()
  subtree:add(fds2.destination_ip_address, buffer(offset, FOUROCTETS), ip)
  offset = offset + FOUROCTETS
  
  ts = buffer(offset, FOUROCTETS):le_uint()
  subtree:add(fds2.timestamp_unix, buffer(offset, FOUROCTETS), ts)
  offset = offset + FOUROCTETS
  
  ts_us = buffer(offset, FOUROCTETS):le_uint()
  subtree:add(fds2.timestamp_microsec, buffer(offset, FOUROCTETS), ts_us)
  offset = offset + FOUROCTETS

  capture_node_id = buffer(offset, TWOOCTETS):le_uint()
  subtree:add(fds2.capture_node_id, buffer(offset, TWOOCTETS), capture_node_id)
  offset = offset + TWOOCTETS

  data_buffer = buffer(offset, TWOOCTETS):le_uint()
  subtree:add(buffer(offset, TWOOCTETS), "Unknown Type: " .. tostring(data_buffer))
  offset = offset + TWOOCTETS
  
  Dissector.get("sip"):call(buffer(offset):tvb(), pinfo, tree)
  
  pinfo.cols.protocol = "HEP2/SIP"

  return
end

function dissect_hep3(buffer, offset, subtree, pinfo, tree)
  hep_version = buffer(offset, FOUROCTETS):string()
  subtree:add(fds3.hep_version, buffer(offset, FOUROCTETS), hep_version)
  offset = offset + FOUROCTETS
  
  total_len = buffer(offset, TWOOCTETS):uint()
  subtree:add(fds3.hep_packet_size, buffer(offset, TWOOCTETS), total_len)

  offset = offset + TWOOCTETS
  chunk_type = get_chunk_data(buffer, offset)
  
  while (offset < (total_len -1)) do
    if chunk_type == "00000001" then
      offset = get_ip_family(buffer, offset, subtree)
    elseif chunk_type == "00000002" then
      offset = get_transport_proto_id(buffer, offset, subtree)
    elseif chunk_type == "00000003" then
      offset = get_source_ipv4_address(buffer, offset, subtree)
    elseif chunk_type == "00000004" then
      offset = get_destination_ipv4_address(buffer, offset, subtree)
    elseif chunk_type == "00000005" then
      offset = get_source_ipv6_address(buffer, offset, subtree)
    elseif chunk_type == "00000006" then
      offset = get_destination_ipv6_address(buffer, offset, subtree)
    elseif chunk_type == "00000007" then
      offset = get_source_port(buffer, offset, subtree)
    elseif chunk_type == "00000008" then
      offset = get_destination_port(buffer, offset, subtree)
    elseif chunk_type == "00000009" then
      offset = get_timestamp(buffer, offset, subtree)
    elseif chunk_type == "0000000a" then
      offset = get_timestamp_microsec(buffer, offset, subtree)
    elseif chunk_type == "0000000b" then
      offset, application_protocol = get_application_protocol(buffer, offset, subtree)
    elseif chunk_type == "0000000c" then
      offset = get_capture_node_id(buffer, offset, subtree)
    elseif chunk_type == "0000000e" then
      offset = get_auth_key(buffer, offset, subtree)
    elseif chunk_type == "0000000f" then
      offset = determine_payload_content(buffer, offset, subtree, pinfo, tree, application_protocol)
    elseif chunk_type == "00000010" then
      -- compressed payload. Treat as normal payload
      -- https://github.com/sipcapture/hep-wireshark/issues/5
      offset = determine_payload_content(buffer, offset, subtree, pinfo, tree, application_protocol)
    elseif chunk_type == "00000011" then
      offset = get_correlation_id(buffer, offset, subtree)
    elseif chunk_type == "00000012" then
      offset = get_vlan_id(buffer, offset, subtree)
    elseif chunk_type == "00000013" then
      offset = get_group_id(buffer, offset, subtree)
    elseif chunk_type == "00000014" then
      offset = get_source_mac(buffer, offset, subtree)
    elseif chunk_type == "00000015" then
      offset = get_destination_mac(buffer, offset, subtree)
    elseif chunk_type == "00000016" then
      offset = get_ethernet_type(buffer, offset, subtree)
    elseif chunk_type == "00000017" then
      offset = get_tcp_flags(buffer, offset, subtree)
    elseif chunk_type == "00000018" then
      offset = get_ip_TOS(buffer, offset, subtree)
    elseif chunk_type == "00000020" then
      offset = get_mos(buffer, offset, subtree)			
    else
      -- proceed unknown chunk
        if (offset < (total_len - 1)) then
		offset = skip_unknown_chunk(buffer, offset)
        end                              
    end

    if (offset < (total_len - 1)) then
      chunk_type = get_chunk_data(buffer, offset)
    end
  end -- while
end

function hep2_proto_dissector(buffer, pinfo, tree)
  local subtree = tree:add(hep2_proto, buffer(), "HEP2 Protocol")
  dissect_hep2(buffer, offset, subtree, pinfo, tree)
end

function hep3_proto_dissector(buffer, pinfo, tree)
  local subtree = tree:add(hep3_proto, buffer(), "HEP3 Protocol")
  dissect_hep3(buffer, offset, subtree, pinfo, tree)
end

function hep_proto.dissector(buffer, pinfo, tree)
  offset = 0
  version = buffer(offset, FOUROCTETS):string()

  if (version == "HEP3") then
    hep3_proto_dissector(buffer, pinfo, tree)
    return
  end
  
  -- Let's try HEP2
  version = buffer(offset, ONEOCTET)

  if (tostring(version) == "02") then
    hep2_proto_dissector(buffer, pinfo, tree)
    return
  else
    -- Not HEP3 or HEP2
  end
end


--
udp_table = DissectorTable.get("udp.port")
udp_table:add(9060, hep_proto)
udp_table:add(9063, hep_proto)

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(9062, hep_proto)
