# HEP over HTTP/HTTP2 Support

This document explains how the HEP dissector supports HTTP and HTTP2 transports for 5G use cases.

## Overview

The HEP dissector now supports dissecting HEP packets transported over HTTP and HTTP2 protocols. This is particularly useful in 5G networks where HEP data may be encapsulated in HTTP-based protocols.

## How It Works

The dissector registers with Wireshark's `media_type` dissector table for the following content types:
- `application/hep`
- `application/vnd.3gpp.hep` (3GPP vendor-specific media type)

When Wireshark encounters an HTTP or HTTP2 response with one of these Content-Type headers, it will automatically invoke the HEP dissector to parse the payload.

## Usage

1. Install the `hep.lua` dissector in your Wireshark plugins folder
2. Capture HTTP or HTTP2 traffic containing HEP data
3. The HEP dissector will automatically recognize and decode HEP packets when:
   - The HTTP response has `Content-Type: application/hep` header, or
   - The HTTP2 response has `Content-Type: application/vnd.3gpp.hep` header

## Example HTTP Request/Response

```http
POST /hep HTTP/1.1
Host: collector.example.com
Content-Type: application/hep
Content-Length: 256

HEP3<binary HEP data>...
```

## Example HTTP2 Frame

HTTP2 frames with the appropriate content-type header will be automatically dissected:

```
HEADERS frame:
  :method: POST
  :path: /hep
  :scheme: https
  content-type: application/vnd.3gpp.hep

DATA frame:
  HEP3<binary HEP data>...
```

## Compatibility

- Works with Wireshark 3.0 and later
- Supports both HTTP/1.x and HTTP/2
- Backward compatible with existing UDP and TCP HEP dissection
