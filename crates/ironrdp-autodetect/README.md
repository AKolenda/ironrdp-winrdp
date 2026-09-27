# IronRDP Auto-Detect

Client network characteristics detection for the main RDP connection, shared by connection establishment, reactivation, and active sessions.
The state machine answers RTT and bandwidth requests without performing I/O or reading a clock.
Its caller supplies decoded requests, incoming byte counts after transport/security headers, and monotonic arrival timestamps.
Lossy UDP detection belongs to its tunnel and is not handled here.

Continuous measurements count each incoming PDU once, including the Stop message.
Connect-time measurements count only Payload and Stop messages, including their eight-byte auto-detect headers.
Without timestamps, replies use a one-millisecond interval and only the connect-time Stop's own bytes (zero bytes for continuous detection).
Move the state into the activation sequence and back into the session to preserve measurements across reactivation.

The protocol procedure is defined in [MS-RDPBCGR 3.2.5.14].

[MS-RDPBCGR 3.2.5.14]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/16ffa852-8aa7-481c-99a0-36c1a9a198f6
