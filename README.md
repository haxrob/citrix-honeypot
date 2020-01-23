# Citrix ADC (NetScaler) Honeypot
- Detects and logs payloads for CVE-2019-19781 (Shitrix / Citrixmash)
- Logs failed login attempts
- Serves content and headers taken from real appliance in order to increase chance of indexing on search engines (e.g. google, shodan etc.)

![screenshot](https://github.com/x1sec/citrix-honeypot/blob/master/img/screenshot.png)

## Installation

### Precompiled
Precompiled Linux (x64) package available [here](https://github.com/x1sec/citrix-honeypot/releases)

```
mkdir citrix-honeypot
cd citrix-honeypot
wget https://github.com/x1sec/citrix-honeypot/releases/download/v0.01/citrix-honeypot-linux-amd64.tar.gz
tar -xf citrix-honeypot-linux-amd64.tar.gz
```

### go get
If you have a [Go](https://golang.org/) environment ready to go:

```bash
go get github.com/x1sec/citrix-honeypot
```

### Running

It's easy as:
```bash
./citrix-honeypot
```

The honeypot will listen on both port `80` and `443`.

Or to detach and run as a background process:
```
nohup ./citrix-honeypot&
```

(`citrix-honeypot` must run with root privledges to listen on the required ports)

Results / data is written to the `./log` directory. They are:

`hits.log` - Scanning attempts and exploitation attempts with all data (e.g. headers, post body)

`all.log` - All HTTP requests that are observed

`logins.log` - Attempted logins to the web interface

`tlsErrors.log` - Often internet scanners will send invalid data to port `443`. HTTPS errors are logged here.
