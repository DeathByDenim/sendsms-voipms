# Send SMS using VoIP.ms
This Python script will let you use your VoIP.ms account to send text messages
using SIP. You only need to provide your log credentials and the desired server.

Usage:
```
sendsms.py [PHONE NUMBER] [MESSAGE]
```

Messages longer than 160 characters are automatically split over multiple text
messages by VoIP.ms

I only tested this with a Sub-Account. It might work with a main account or with
IP authentication as well, but this is untested.
