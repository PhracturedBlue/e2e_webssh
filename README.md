# e2e_webssh
Based on https://github.com/Razikus/go-ssh-to-websocket

This utility uses xterm.js to create a Web SSH portal with end-to-end encryption.
The idea is to secure traansmission betwene the server and client even when using a MITM proxy like cloudflare.
Traffic is encrypted via symmetric AES-256 encryption, using 2FA authentication (a known password and a TOTP key).
Additionally, the salt is a random value transmitted from the server to the client.
This means that even if your password were to be intercepted, new conections could not be started without also knowing the TOTP secret.
Also, unless the TOTP code was also interecpted, any prior sessions should also be secure against decrypting.

The primary weakness of this approach is that the MITM proxy is serving the html and javascript and could inject code to save the password/code.
That could be avoided by reading the html/xterm.js from a trusted source, or stroing it locally

## Protecting commandline arguments from snooping.
To superfically protect commandline arguments (password, TOTP secrets) from casual snooping (ps or the like), these arguments are
encrypted with a key embeded in the executable.  This is only meant to hid these parameters from casual observation, and does not
provide any security beyond that

## Building:
Building is done twice.  The 1st time will generate an internal key for superficially protecting commandline arguments.  The second
time generates the final executable

go build
./e2e_webssh

go build -ldflags '-s -w -X main.aeskey=<put key here>
