# Citrix ADC (NetScaler) Honeypot
- Detects and logs payloads for CVE-2019-19781 (Shitrix / Citrixmash)
- Logs failed login attempts
- Serves content and headers taken from real appliance in order to increase chance of indexing on search engines (e.g. google, shodan etc.)

![screenshot](https://github.com/x1sec/citrix-honeypot/blob/master/img/screenshot.png)

## Installation

Precompiled Linux (x64) package available [here](https://github.com/x1sec/citrix-honeypot/releases)

If you have a [Go](https://golang.org/) environment ready to go:

```bash
go get github.com/x1sec/citrix-honeypot
```

You must provide certificate to serve HTTPS. To generate your own:
```
openssl genrsa -out server.key 2048
openssl ecparam -genkey -name secp384r1 -out server.key
openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
```

### Running

It's easy as:
```bash
./citrix-honeypot
```

The honeypot will listen on both port `80` and `443`.

Or to detach and run as a background process:
```
$ nohup ./citrix-honeypot&
```

Results / data is written to the `./log` directory. They are:

`hits.log` - Scanning attempts and exploitation attempts with all data (e.g. headers, post body)

`all.log` - All HTTP requests that are observed

`logins.log` - Attempted logins to the web interface

`tlsErrors.log` - Often internet scanners will send invalid data to port `443`. HTTPS errors are logged here.
