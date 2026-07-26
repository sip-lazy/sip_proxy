#
#      Start Docker container: SIP proxy for web phone.
#
#      The certificate and public key files are expected to be located in
#      /etc/ssl/private with the filenames tls.crt and tls.key
#
#      Edit the .env file to set the usernames and passwords (see USERS=).
#
if [[ $(docker ps --format '{{.Names}}' | grep sip_proxy) ]]; then
  docker stop sip_proxy
fi

if [[ $(docker ps -a --format '{{.Names}}' | grep sip_proxy) ]]; then
  docker rm sip_proxy
fi

echo starting sip proxy container
docker run --name sip_proxy \
	-d \
    --restart=unless-stopped \
    -v /etc/ssl/private:/etc/ssl:ro\
    -p 443:443 \
    sip_proxy:1.0.0

