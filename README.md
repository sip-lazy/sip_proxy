### sip_proxy

A lightweight, standalone SIP proxy built specifically to connect directly with WebRTC web phones over WebSockets—without needing a separate SIP backend server. 

The proxy is designed to be deployed on cloud Linux servers configured with a static IP, a Fully Qualified Domain Name (FQDN), and a valid SSL/TLS certificate. 

### Compatibility Notice

This proxy should work with any WebRTC browser phone, but it was tested only in a JsSIP-based one. 

### Prerequisites & Deployment

### 1. Port and Firewall Configuration

By default, secure WebSockets utilize port 443. However, you can configure the proxy to use any alternative custom port. If you change the port, you must complete the following two steps: 

* Firewall Rule: Manually open the incoming TCP port in your cloud provider's firewall (e.g., AWS Security Groups, DigitalOcean Firewalls, UFW) to allow external traffic.
* Script Modification: Open and edit the ./start.sh file to bind the container mapping to your chosen custom port.

### 2. SSL/TLS Certificate Setup

The proxy requires valid SSL certificates to handle secure WebSocket connections. Place your files in the default location: 

* Certificate: /etc/ssl/private/tls.crt
* Private Key: /etc/ssl/private/tls.key

Note: If you use a different directory for your certificates, open and edit the volume mappings inside the ./start.sh file. 

### 3. Build the Application

The proxy runs inside Docker. Build the container by running: 

bash

./build.sh

Use code with caution.

### 4. Configuration (.env)

Configure your authorized web phone extensions by editing the USERS section inside your .env file: 

env

USERS=username:password,user2:pass2

Use code with caution.

### 5. Run the Proxy

Start the container using the startup script: 

bash

./start.sh

Use code with caution.

### Web Phone Configuration (Important Note on NAT Traversal)

While the proxy handles the signaling, NAT traversal must be configured on your WebRTC web phone client. Because mobile providers and home routers use Carrier-Grade NAT (CGNAT) or symmetric NAT, your web phone client needs access to STUN/TURN servers to establish audio/video media paths. 

When configuring your web phone instance (such as a JsSIP client), ensure your pcConfig (RTCConfiguration) includes appropriate ICE servers: 

* Standard Networks: A free public STUN server is usually enough: 

javascript

iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]

Use code with caution.
* Strict/Mobile Networks (CGNAT): A dedicated TURN server is required. This proxy has been fully tested using an eturnal TURN server setup: 

javascript

iceServers: [
  { urls: 'stun:stun.your-eturnal-server.com:3478' },
  { 
    urls: 'turn:turn.your-eturnal-server.com:3478', 
    username: 'your_turn_user', 
    credential: 'your_turn_password' 
  }
]

Use code with caution.

### Credits & License

This project incorporates components from the JsSIP repository under the MIT License. 

* Unmodified Files: Grammar.pegjs and grammar.js are utilized to process and validate standard SIP syntax.
* Modified Core: SipMessage.js has been deeply modified to allow direct, flexible header injection and modification required for this standalone proxy environment.

Original JsSIP code Copyright (c) 2012-2021 José Luis Millán, Iñaki Baz Castillo. 

Licensed under the MIT License.
