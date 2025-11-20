# Wireshark dissector for HEP protocol

This dissector supports both HEP version 2 and 3.

## The HEP protocol

### HEP3

https://github.com/sipcapture/HEP/blob/master/docs/HEP3_rev12.pdf

## Supported Transports

The dissector supports HEP over the following transports:
- **UDP** (ports 9060, 9063)
- **TCP** (ports 9060, 9062)
- **HTTP** (via media types: `application/hep`, `application/vnd.3gpp.hep`)
- **HTTP2** (via media types: `application/hep`, `application/vnd.3gpp.hep`)

HTTP/HTTP2 support enables HEP dissection in 5G environments where HEP packets are transported over HTTP-based protocols.

## Install dissector

Check in `About Wireshark` -> `Folders` where plugins are installed. Then drop hep.lua inside the Personal or Global Plugins folder.

e.g. of personal folder: `~/.config/wireshark/plugins/`

## Libraries used

https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html
