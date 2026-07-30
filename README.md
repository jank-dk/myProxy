Simple reverse proxy I use to debug local instances of a service running in a kubernetes cluster, but I still need other parts of the services from the cluster to be available

I had a problem with mitmproxy, where the POST body sometimes was not relayed correctly to the underlying service if I used a python script to route requests

You need a CA certificate added to the computer's certificate store in Trusted Root Certificates. If you already have mitmproxy, chances are you already have one. Then you can point myProxy to use the same CA as mitmproxy by using ~/.mitmproxy/mitmproxy-ca.pem

myProxy will then generate a certificate based on the CA for the host name you choose on the command line

You also need a rules json file.

Example rules.json:
```json
[
  { "path": "/test", "statictext": "Hello world" },
  { "path": "/server1", "destination": "http://localhost:8080" },
  { "path": "/server2", "destination": "http://localhost:8081" }
]
```

I usually set up some portforwards into my cluster to the "real" services that I want to be accessible from the proxy, but urls pointing to other servers should work fine as well.
If statictext is set, you simply get a 200 OK result containing the text from statictext.

Path follows the rules ServerMux from net/http in the Go language

Example:
| Path | Explanation |
| --- |  --- |
| GET / | matches all GET requests (put this last if you have other rules you want matched as well) |
| GET /test | matches a GET request on path test |
| GET /test/ | matches all GET requests on path test and below |
| POST /asdf | matches a POST request on path asdf |
| /test | matches anything on path test |
| /test/ | matches anything on path test and below |

Paths without a trailing slash only matches the exact path

Command line arguments:
| Argument | Type | Description |
| --- | --- | --- |
| -help | | Show help |
| -verbose | | Verbose output |
| -hostname | string | The host name to serve TLS for |
| -pemfile | string | The file where the certificate and private key is stored for the CA (default "ca.pem") |
| -port | int | The port to listen on (default 443) |
| -rules | string | What file to read the proxy rules from (default "rules.json") |
