# Ziti Router Auto Enroll

[![Pylint](https://github.com/netfoundry/ziti_router_auto_enroll/actions/workflows/pylint.yml/badge.svg)](https://github.com/netfoundry/ziti_router_auto_enroll/actions/workflows/pylint.yml)

This Python script automates the process of downloading, configuring and enrolling an OpenZiti router. The script takes care of generating the configuration file with custom options, downloading binaries from github, handling the enrollment process, and setting up local DNS settings if needed.

## Requirements

### Running compiled binary
- Ubuntu 20.04 or higher
### Running with python
- Ubuntu 20.04 or higher
- Python 3.6 or higher
- Install requirements: `pip install -r requirements.txt`

## Main Features

1. **Automated enrollment**: The script can enroll a Ziti edge router using a provided JWT or by connecting to the controller to create a new router.
2. **Configuration generation**: The script generates a configuration file using Jinja2 templates, with support for customizing various settings.
3. **Binary install**: The script will download and extract the ziti binaries allowing you to choose an install path or the default /opt/ziti.
3. **DNS handling**: The script can configure the system's DNS settings based on the operating system if tunnel is enabled, currently supporting Ubuntu.
4. **Re-Registering**: The script can be used on a system already registered & will stop the services before proceeding with the re-registration process.

## Examples

`./ziti_router_auto_enroll {paste JWT here}` OR `./ziti_router_auto_enroll --jwt enrollment.txt`

- "Private" - This is the default edge-router configuration with the interface is that used as the default GW. This will create a edge listner. This will & only accept ziti SDK connections on port 443 & healthchecks on port 8081. "Private" meaning it's using local interface IP.


`./ziti_router_auto_enroll --jwt enrollment.txt --assumePublic`

- "Public" - This will change the default edge listner by using whatever external IP is used outbound instead of the local interface IP/name.   This also add a link listner using the same external IP. This will & accept ziti SDK connections on port 443 & other router links on port 80 & healthchecks on port 8081. "Public" meaning it's going to do an external IP lookup & use that value instead of the local interface IP.

`./ziti_router_auto_enroll --jwt enrollment.txt --autoTunnelListener`
- "Private with local Tunneler enabled" - This will change the default to add a local Tunnel listner using the the interface is that used as the default GW & will attempt to configure the local DNS so the local interface is the first resolver for the OS.


## Main Options

**One positional argument**, a jwt string which is optional.(enrollment_jwt)

- `-j JWT`, `--jwt JWT`: Path to file-based JWT
- `-p`, `--printConfig`: Print the generated configuration and exit
- `-t`, `--printTemplate`: Print the Jinja template used to create the config and exit
- `-n`, `--noHostname`: Don't use hostnames, only IP addresses for auto-generated config
- `-f`, `--force`: Forcefully proceed with re-enrollment
- `-l {DEBUG,INFO,WARNING,ERROR,CRITICAL}`, `--logLevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}`: Set the logging level (Default: INFO)
- `-v`, `--version`: Show the program's version number and exit

## Install Options

- `--logFile`: Specify the log file (Default: `{cwd}/{program_name}.log`)
- `--parametersFile`: File containing all parameters Json or Yaml format (.json or .yaml/.yml)
- `--installDir`: Installation directory for Openziti (Default: `/opt/openziti/ziti-router`)
- `--installVersion`: Install a specific version (Default is to match Controller)
- `--downloadUrl`: Bundle download URL (Default: `https://github.com/openziti/ziti/releases/latest/`)

## Configuration Options
### Router Identity Paths

- `--identityCert`: Path to certificate (Default: `{installDir}/certs/cert.pem`)
- `--identityServerCert`: Path to server chain (Default: `{installDir}/certs/server_cert.pem`)
- `--identityKey`: Path to key file (Default: `{installDir}/certs/key.pem`)
- `--identityCa`: Path to CA chain (Default: `{installDir}/certs/ca.pem`)

### Controller options

- `--controller`: Hostname or IP of Openziti controller
- `--controllerMgmtPort`: Controller Edge Port
- `--controllerFabricPort`: Controller Fabric Port

### Proxy options

- `--proxyType`: Proxy type, currently supported is "http" (Default: `http`)
- `--proxyAddress`: The Address of the proxy (Default: `None`)
- `--proxyPort`: The port of the proxy (Default: `3128`)
### HealthCheck Options

- `--disableHealthChecks`: Disable HealthChecks portion of router config
  - Note: If you disable HealthChecks, the web section is also automatically disabled.
- `--ctrlPingCheckInterval`: How often to ping the controller (Default: 30)
- `--ctrlPingCheckTimeout`: Timeout the ping (Default: 15)
- `--ctrlPingCheckInitialDelay`: How long to wait before pinging the controller (Default: 15)
- `--linkCheckMinLinks`: Number of links required for the health check to be passing. (Defaults to 1)
- `--linkCheckInterval`: How often to check the link count. (Defaults to 5)
- `--linkCheckInitialDelay`: How long to wait before running the first check. (Defaults to 5)

### Metrics Options

- `--reportInterval`: Reporting Interval (Default: 15)
- `--messageQueueSize`: Message Queue Size (Default: 10)

### Edge Options
- `--disableEdge`: Disable the Edge portion of router config
- `--heartbeatIntervalSeconds`: Edge heartbeatInterval in Seconds (Default: 60)
- `--csrCountry`: Country in certificate (Default: US)
- `--csrProvince`: Province in certificate (Default: NC)
- `--csrLocality`: Locality in certificate (Default: Charlotte)
- `--csrOrganization`: Organization in certificate (Default: NetFoundry)
- `--csrOrganizationalUnit`: OrganizationalUnit in certificate (Default: Ziti)
- `--csrSansEmail`: SANS Email
- `--csrSansDns`: List of SANS DNS names
- `--csrSansIp`: List of SANS IP Addresses
- `--csrSansUri`: List of SANS URIs

### API Proxy Options
- `--apiProxyListener`: The interface and port that the Edge API should be served on.
    - Format: 'Listner'
      - Example: --apiProxyListener '0.0.0.0:1080'
- `--apiProxyUpstream`: The hostname and port combination to the ziti-controller hosted Edge API
    - Format: 'Upstream'
      - Example: --apiProxyUpstream 'mycontrollerhostname:1080'

### Link Options
- `--linkDialers`: Link Dialers (Default: 'transport')
    - Format: 'BINDING' 'BIND'
    - Binding (required): The binding type ('transport')
    - Bind (optional): The network interface used to dial the controller and router links can be ip or interface name.
      - Examples: 
        - --linkDialers 'transport' '0.0.0.0'
        - --linkDialers 'transport' 'eth0'

- `--linkListeners`: Link Listener (Default: None)
    - Format: 'BINDING' 'BIND' 'ADVERTISE' 'OUTQUESIZE'
    - Binding (required): The binding type ('transport')
    - Bind (required): A protocol:host:port string on which network interface to listen on. 0.0.0.0 will listen on all interfaces
    - Advertise (required): The protocol:host:port combination other router should use to connect.
    - OutQueSize (optional): The queue size for #TODO
      - Example: --linkListeners 'transport' 'tls:0.0.0.0:80' 'tls:myhost:80' '16'

### Listeners Options
- `--disableListeners`: Disable Listeners portion of router config
- `--assumePublic`: Attempt to use external lookup to assign default edge listener instead of {default_gw_adapter} - This option also auto configures an external linkListener with the external ip
- `--edgeListeners`: Edge Binding Listener (Default: 'tls:0.0.0.0:443' '{default_gw_adapter}:443')
    - Format: 'ADDRESS' 'ADVERTISE' 'MAXQUEUEDCONNECTS' 'MAXOUTSTANDINGCONNECTS' 'CONNECTTIMEOUTMS' 'LOOKUPAPISESSIONTIMEOUT'
    - Address (required): A protocol:host:port string on which network interface to listen on. 0.0.0.0 will listen on all interfaces
    - Advertise (required): The public hostname and port combination that Ziti SDKs should connect on.
    - MaxQueuedConnects (optional): Set the maximum number of connect requests that are buffered and waiting to be acknowledged (1 to 5000, default 1000)
    - MaxOutstandingConnects (optional): The maximum number of connects that have  begun hello synchronization (1 to 1000, default 16)
    - ConnectionTimeoutMS (optional): The number of milliseconds to wait before a hello synchronization fails and closes the connection (30ms to 60000ms, default: 1000ms)
    - LookupApiSessionTimeout(optional): How long to wait before timing out when looking up api-sessions after client connect. Default 5 seconds.
      - Examples: 
        - --edgeListeners 'tls:0.0.0.0:443' 'myhost:443' '1000' '16' '1000' '5'
        - --edgeListeners 'wss:0.0.0.0:443' 'myhost:7001'

- `--proxyListeners`: Proxy Binding Listener (Default: None)
    - Format: 'ADDRESS' 'SERVICE'
    - Address (required): A protocol:host:port string on which network interface to listen on. 0.0.0.0 will listen on all interfaces
    - Service (required): The name of the ziti service to connect.
      - Example: --proxyListeners 'tcp:0.0.0.0:123' 'my_ntp_service'
      
- `--tunnelListener`: Tunnel Binding Listener (Default: None)
    - Format: 'MODE' 'RESOLVER' 'LANIF'
    - Mode (required): Tunnel mode ('tproxy', 'host', 'proxy')
    - Resolver (optional): A protocol:host:port string on which network interface to listen on.
    - LanIf (optional): The lan interface to create to create tproxy rules.
      - Example: --tunnelListener 'tproxy' 'udp://127.0.0.1:53' 'eth0'
      - Note: 'tproxy' requires all three options
    - DnsSvcIpRange (optional): cidr to use when assigning IPs to unresolvable intercept hostnames (default "100.64.0.0/10")
- `--autoTunnelListener`: Automatically add a local tproxy tunneler with the {default_gw_adapter} as the local resolver and LANIf

### Web Options
- `--webs`: Web Options (Default: 'health-check' '0.0.0.0:8081' '0.0.0.0:8081' 'health-checks')
    - Format: 'NAME' 'INTERFACE' 'ADDRESS' 'BINDING'
    - Name(required): Provides a name for this listener, used for logging output. Not required to be unique, but is highly suggested.
    - Interface(required): A host:port string on which network interface to listen on. 0.0.0.0 will listen on all interfaces
    - Address(required): The public address that external incoming requests will be able to resolve.
    - Binding(required): Specifies an API to bind to this webListener. Built-in APIs are
      - Example: --webs 'health-check' '0.0.0.0:8081' '0.0.0.0:8081' 'health-checks'

## Router Creation Options

Create a new router on the controller before enrollment:

- `--adminUser`: Openziti Admin username
- `--adminPassword`: Openziti Admin password
- `--routerName`: Router name created in controller

## Passing arguments values

Besides passing in every argument with a --argumentName you can also use:

  - OS Environment 
  - A Parameters file
### Using Environmental Variables

:heavy_exclamation_mark: When using environment variables make sure to use **sudo -E** when running the command

You can pass any argument vi OS Environmental variables.  All argument are in all UPPER case.

:warning: Passing in links, listeners, tunnelers, webs is not supported.  Passing a list of lists with environment is messy. Use the json or yaml instead.

Example: `export CONTROLLERFABRICPORT=6262`
Example: `export CSRSANSDNS="name1,name2,name3"

### Using parameter file
You can pass any argument vi paramter files.  Json or Yaml format is supported.
The file extension needs to be .json or .yaml/.yml

Example Json:
```
{
  "controllerFabricPort": 6262
  "csrSansIp": ["1.1.1.1","2.2.2.2"],
  "proxyListeners": [["0.0.0.0:123","my_ntp_service"],["0.0.0.0:5631","mydbconn_service"]]
}
```
Example Yaml:
```
controllerFabricPort: 6262
csrSansIp:
  - 1.1.1.1
  - 2.2.2.2
proxyListeners:
  - ["0.0.0.0:123", "myntp"]
  - ["0.0.0.0:5631", "mydb"]
```
