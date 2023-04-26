#!/usr/bin/env python
"""
Ziti Router Automated Enrollment
"""
import sys
import time
from urllib.parse import urlparse
import argparse
import tarfile
import socket
import os
import logging
import json
import subprocess
import platform
import ipaddress
import yaml
import distro
import psutil
from packaging.version import Version
from tqdm import tqdm
import jwt
from colorama import Fore, Style, init
from jinja2 import Template
import requests
import urllib3

CONFIG_TEMPLATE_STRING = ("""v: 3
identity:
  cert: {{ identity.cert }}
  server_cert: {{ identity.server_cert }}
  key: {{ identity.key }}
  ca: {{ identity.ca }}
ctrl:
  endpoint: {{ ctrl.endpoint }}
link:
  dialers:
  {%- for dialer in link_dialers %}
    - binding: {{ dialer.binding }}
      {%- if dialer.bind is defined %}
      bind: {{ dialer.bind }}
      {%- endif %}  
  {%- endfor %}
  {%- if link_listeners %}
  listeners:
  {%- endif %}
    {%- for listener in link_listeners %}
    - binding: {{ listener.binding }}
      bind: {{ listener.bind }}
      advertise: {{ listener.advertise }}
      options:
        {%- if listener.options.outqueuesize is defined %}
        outQueueSize: {{ listener.options.outqueuesize }}
        {%- endif %}
    {%- endfor %}

{%- if healthChecks is defined %}
healthChecks:
  ctrlPingCheck:
    interval: {{ healthChecks.ctrlPingCheck.interval }}
    timeout: {{ healthChecks.ctrlPingCheck.timeout }}
    initialDelay: {{ healthChecks.ctrlPingCheck.initialDelay }}
{%- endif %}

{%- if metrics is defined %}
metrics:
  reportInterval: {{ metrics.reportInterval }}
  messageQueueSize: {{ metrics.messageQueueSize }}
{%- endif %}

{%- if edge is defined %}
edge:
{%- if edge.heartbeatIntervalSeconds is defined %}
  heartbeatIntervalSeconds: {{ edge.heartbeatIntervalSeconds }}
{%- endif %}
  csr:
    country: {{ edge.csr.country }}
    province: {{ edge.csr.province }}
    locality: {{ edge.csr.locality }}
    organization: {{ edge.csr.organization }}
    organizationalUnit: {{ edge.csr.organizationalUnit }}
    sans:
    {%- if edge.csr.sans.dns is defined %}
      dns:
        {%- for dns in edge.csr.sans.dns %}
        - {{ dns }}
        {%- endfor %}
    {%- endif %}
    {%- if edge.csr.sans.email is defined %}
      email:
        {%- for email in edge.csr.sans.email %}
        - {{ email }}
        {%- endfor %}
    {%- endif %}
    {%- if edge.csr.sans.ip is defined %}
      ip:
        {%- for ip in edge.csr.sans.ip %}
        - {{ ip }}
        {%- endfor %}
    {%- endif %}
    {%- if edge.csr.sans.uri is defined %}
      uri:
        {%- for uri in edge.csr.sans.uri %}
        - {{ uri }}
        {%- endfor %}
    {%- endif %}
{%- endif %}
{%- if apiProxy is defined %}
apiProxy:
  listener: {{ apiProxy.listener }}
  upstream: {{ apiProxy.upstream }}
{%- endif %}


{%- if listeners is defined %}
listeners:
{%- endif %}
{%- for listener in listeners %}
  - binding: {{ listener.binding }}
    {%- if listener.address is defined %}
    address: {{ listener.address }}
    {%- endif %}
    {%- if listener.service is defined %}
    service: {{ listener.service }}
    {%- endif %}
    {%- if listener.options is defined %}
    options:
      {%- if listener.options.advertise is defined %}
      advertise: {{ listener.options.advertise }}
      {%- endif %}
      {%- if listener.options.maxQueuedConnects is defined %}
      maxQueuedConnects: {{ listener.options.maxQueuedConnects }}
      {%- endif %}
      {%- if listener.options.maxOutstandingConnects is defined %}
      maxOutstandingConnects: {{ listener.options.maxOutstandingConnects }}
      {%- endif %}
      {%- if listener.options.connectTimeoutMs is defined %}
      connectTimeoutMs: {{ listener.options.connectTimeoutMs }}
      {%- endif %}
      {%- if listener.options.lookupApiSessionTimeout is defined %}
      lookupApiSessionTimeout: {{ listener.options.lookupApiSessionTimeout }}
      {%- endif %}
      {%- if listener.options.mode is defined %}
      mode: {{ listener.options.mode }}
      {%- endif %}
      {%- if listener.options.resolver is defined %}
      resolver: {{ listener.options.resolver }}
      {%- endif %}
      {%- if listener.options.lanIf is defined %}
      lanIf: {{ listener.options.lanIf }}
      {%- endif %}  
    {%- endif %}                  
{%- endfor %}

{%- if webs is defined %}
web:
{%- for web in webs %}
- name: {{ web.name }}
  bindPoints:
    - interface: {{ web.bindpoints.interface }}
      address: {{ web.bindpoints.address }}
  apis:
    - binding: {{ web.apis.binding }}
{%- endfor %}
{%- endif %}""")

SYSTEMD_UNIT_TEMPLATE_STRING =("""
[Unit]
Description=Ziti-Router
After=network.target

[Service]
User=root
WorkingDirectory={{ install_dir }}
ExecStartPre=-/usr/sbin/iptables -F NF-INTERCEPT -t mangle
ExecStartPre=-/opt/netfoundry/ebpf/objects/etables -F -r
ExecStartPre=-/opt/netfoundry/ebpf/scripts/tproxy_splicer_startup.sh
{% if single_binary -%}
ExecStart={{ install_dir }}/ziti router run {{ install_dir }}/config.yml
{%- else -%}
ExecStart={{ install_dir }}/ziti-router run {{ install_dir }}/config.yml
{%- endif %}
Restart=always
RestartSec=2
LimitNOFILE=65535
AmbientCapabilities=CAP_NET_BIND_SERVICE
SyslogIdentifier=ziti-router

[Install]
WantedBy=multi-user.target
"""
)

def add_general_arguments(parser, version):
    """
    Add general arguments to the parser.

    :param parser: The argparse.ArgumentParser instance to add the arguments to.
    :param version: The version string for the --version argument.
    """
    parser.add_argument('enrollment_jwt', nargs='?',
                        help='Enrollment JWT String')
    parser.add_argument('-j','--jwt', type=str,
                        help='Path to file based jwt')
    parser.add_argument('-p', '--printConfig',
                        action="store_true",
                        help='Print the generated configuration and exit')
    parser.add_argument('-t', '--printTemplate',
                        action="store_true",
                        help='Print the jinja template used to create the config and exit')
    parser.add_argument('-n', '--noHostname',
                        action='store_true',
                        help='Dont use hostnames only IP addresses for auto generated config')
    parser.add_argument('-f', '--force',
                        action="store_false",
                        help='Forcefully proceed with re-enrollment',
                        default=True)
    parser.add_argument('-l', '--logLevel', type=str,
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        default='INFO', help='Set the logging level - Default: INFO)')
    parser.add_argument('-v', '--version',
                        action='version',
                        version=version)

def add_install_arguments(parser):
    """
    Add install options arguments to the parser.

    :param parser: The argparse.ArgumentParser instance to add the arguments to.
    """
    install_config = parser.add_argument_group('Install options')
    install_config.formatter_class = argparse.ArgumentDefaultsHelpFormatter
    install_config.add_argument('--logFile', type=str,
                                help='Specify the log file -'
                                     'Default {cwd}/{program_name}}.log')
    install_config.add_argument('--parametersFile', type=str,
                                help='File containing all parameters - json or yaml')
    install_config.add_argument('--installDir', type=str,
                                help='Installation directory for Openziti - '
                                     'Default /opt/ziti',
                                default='/opt/ziti')
    install_config.add_argument('--installVersion', type=str,
                                help='Install specific version - '
                                     'Default is to match Controller')
    install_config.add_argument('--downloadUrl', type=str,
                                help='Bundle download url - '
                                     'Default https://github.com/openziti/ziti/releases/latest/')

def add_router_identity_arguments(parser):
    """
    Add identity options arguments to the parser.

    :param parser: The argparse.ArgumentParser instance to add the arguments to.
    """
    router_identity_config_group = parser.add_argument_group('Router Identity Paths')
    router_identity_config_group.add_argument('--identityCert', type=str,
                                              help='Path to certificate - '
                                                   'Default {installDir}/certs/cert.pem')
    router_identity_config_group.add_argument('--identityServerCert', type=str,
                                              help='Path to server chain - '
                                                   'Default {installDir}/certs/server_cert.pem')
    router_identity_config_group.add_argument('--identityKey', type=str,
                                              help='Path to key file - '
                                                   'Default {installDir}/certs/key.pem')
    router_identity_config_group.add_argument('--identityCa', type=str,
                                              help='Path to ca chain - '
                                                   'Default {installDir}}/certs/ca.pem')

def add_router_ctrl_arguments(parser):
    """
    Add ctrl options arguments to the parser.

    :param parser: The argparse.ArgumentParser instance to add the arguments to.
    """
    router_ctrl_config_group = parser.add_argument_group('Controller Options')
    router_ctrl_config_group.add_argument('--controller',type=str,
                                     help='Hostname or IP of Openziti controller')
    router_ctrl_config_group.add_argument('--controllerFabricPort',type=int,
                                     help='Controller Fabric Port'
                                          'Default 80',
                                     default=80)
    router_ctrl_config_group.add_argument('--controllerMgmtPort',type=int,
                                     help='Controller Management Port'
                                          'Default 443',
                                     default=443)

def add_router_health_checks_arguments(parser):
    """
    Add health checks options arguments to the parser.

    :param parser: The argparse.ArgumentParser instance to add the arguments to.
    """
    router_health_checks_group = parser.add_argument_group('HealthCheck Options')
    router_health_checks_group.add_argument('--disableHealthChecks',
                                            action='store_false',
                                            help='Disable HealthChecks',
                                            default=True)
    router_health_checks_group.add_argument('--ctrlPingCheckInterval', type=int, default=30,
                                            help='How often to ping the controller - '
                                                 'Default 30')
    router_health_checks_group.add_argument('--ctrlPingCheckTimeout', type=int, default=15,
                                            help='Timeout the ping - '
                                                 'Default 15')
    router_health_checks_group.add_argument('--ctrlPingCheckInitialDelay', type=int, default=15,
                                            help='How long to wait before pinging the controller - '
                                                 'Default 15')

def add_router_metrics_arguments(parser):
    """
    Add metrics options arguments to the parser.

    :param parser: The argparse.ArgumentParser instance to add the arguments to.
    """
    router_metrics_group = parser.add_argument_group('Metrics Options')
    router_metrics_group.add_argument('--disableMetrics',
                                      action='store_false',
                                      help='Disable the Metrics',
                                      default=True)
    router_metrics_group.add_argument('--reportInterval',type=int, default=15,
                                      help='Reporting Interval - '
                                           'Default 15')
    router_metrics_group.add_argument('--messageQueueSize',type=int, default=10,
                                      help='Message Queue Size - '
                                           'Default 10')

def add_router_edge_arguments(parser):
    """
    Add edge options arguments to the parser.

    :param parser: The argparse.ArgumentParser instance to add the arguments to.
    """
    router_edge_config_group = parser.add_argument_group('Edge Options')
    router_edge_config_group.add_argument('--disableEdge',
                                          action='store_false',
                                          help="Disable the Edge",
                                          default=True)
    router_edge_config_group.add_argument('--heartbeatIntervalSeconds',
                                          help='Edge heartbeatInterval in Seconds - '
                                               'Default 60',
                                          default=60,
                                          type=int)
    router_edge_config_group.add_argument('--csrCountry',
                                          help='Country in certificate - '
                                               'Default US',
                                          default='US')
    router_edge_config_group.add_argument('--csrProvince',
                                          help='Province in certificate - '
                                               'Default NC',
                                          default='NC')
    router_edge_config_group.add_argument('--csrLocality',
                                          help='Locality in certificate - '
                                               'Default Charlotte',
                                          default='Charlotte')
    router_edge_config_group.add_argument('--csrOrganization',
                                          help='Organization in certificate - '
                                               'Default NetFoundry',
                                          default='NetFoundry')
    router_edge_config_group.add_argument('--csrOrganizationalUnit',
                                          help='OrganizationalUnit in certificate -'
                                               'Default Ziti',
                                          default='Ziti')
    router_edge_config_group.add_argument('--csrSansEmail',
                                          action='append',
                                          help='SANS Email')
    router_edge_config_group.add_argument('--csrSansDns',
                                          action='append',
                                          help='List of SANS DNS names')
    router_edge_config_group.add_argument('--csrSansIp',
                                          action='append',
                                          help='List of SANS IP Addresses')
    router_edge_config_group.add_argument('--csrSansUri',
                                          action='append',
                                          help='List of SANS URIs')

def add_router_api_proxy_arguments(parser):
    """
    Add api proxy options arguments to the parser.

    :param parser: The argparse.ArgumentParser instance to add the arguments to.
    """
    router_proxy_config = parser.add_argument_group('API Proxy')
    router_proxy_config.add_argument('--apiProxyListener', default=[],
                                          help='ProxyListener')
    router_proxy_config.add_argument('--apiProxyUpstream', default=[],
                                          help='ProxyUpstream')

def add_router_fabric_link_arguments(parser):
    """
    Add fabric link options arguments to the parser.

    :param parser: The argparse.ArgumentParser instance to add the arguments to.
    """
    router_fabric_link_group = parser.add_argument_group('Link Options')
    router_fabric_link_group.add_argument('--linkDialers',
                                          action='append',
                                          nargs='+',
                                          metavar=('BINDING BIND'),
                                          help='Link Dialers - '
                                          'Default \'transport\'')
    router_fabric_link_group.add_argument('--linkListeners',
                                          action='append',
                                          nargs='+',
                                          metavar=('BINDING BIND ADVERTISE OUTQUESIZE'),
                                          help='Link Listener - '
                                               'Default None')

def add_router_listener_arguments(parser):
    """
    Add listner options arguments to the parser.

    :param parser: The argparse.ArgumentParser instance to add the arguments to.
    """
    router_listener_group = parser.add_argument_group('Listeners Options')
    router_listener_group.add_argument('--disableListeners',
                                       action='store_false',
                                       help='Disable Listeners',
                                       default=True)
    router_listener_group.add_argument('--assumePublic',
                                       action='store_true',
                                       help='Attempt to use external '
                                            'lookup to assign default edge listener '
                                            'instead of {default_gw_adapter}')
    router_listener_group.add_argument('--edgeListeners',
                                       action='append',
                                       nargs='+',
                                       metavar=('ADDRESS ADVERTISE '
                                                'MAXQUEUEDCONNECTS '
                                                'MAXOUTSTANDINGCONNECTS '
                                                'CONNECTTIMEOUTMS '
                                                'LOOKUPAPISESSIONTIMEOUT'),
                                       help='Edge Binding Listener - '
                                            'Default \'edge\' '
                                            '\'tls:0.0.0.0:443\' '
                                            '\'{default_gw_adapter}:443\'')
    router_listener_group.add_argument('--proxyListeners',
                                       action='append',
                                       nargs=2,
                                       metavar=('ADDRESS','SERVICE'),
                                       help='Proxy Binding Listener - '
                                            'Default None')
    router_listener_group.add_argument('--tunnelListener',
                                       nargs=3,
                                       metavar=('MODE','RESOLVER','LANIF'),
                                       help='Tunnel Binding Listener - '
                                            'Default None')
    router_listener_group.add_argument('--autoTunnelListener',
                                       action='store_true',
                                       help='Automatically add a local tproxy tunneler '
                                            'with the {default_gw_adapter} as the local resolver '
                                            'and LANIf',
                                       default=False)

def add_router_web_arguments(parser):
    """
    Add web options arguments to the parser.

    :param parser: The argparse.ArgumentParser instance to add the arguments to.
    """
    router_web_group = parser.add_argument_group('Web Options')
    router_web_group.formatter_class = argparse.ArgumentDefaultsHelpFormatter
    router_web_group.add_argument('--webs',
                                  action='append',
                                  nargs='+',
                                  metavar=('NAME INTERFACE ADDRESS BINDING'),
                                  help=('Web Options - '
                                        'Default \'health-check\' '
                                        '\'0.0.0.0:8081\' '
                                        '\'0.0.0.0:8081\' '
                                        '\'health-checks\''))

def add_create_router_arguments(parser):
    """
    Add create options arguments to the parser.

    :param parser: The argparse.ArgumentParser instance to add the arguments to.
    """
    create_router_group = parser.add_argument_group(
                    'Router Creation Options: '
                    'Create new router on the controller before enrollment')
    create_router_group.add_argument('--adminUser',type=str,
                                     help="Openziti Admin username")
    create_router_group.add_argument('--adminPassword',type=str,
                                     help='Openziti Admin passowrd')
    create_router_group.add_argument('--routerName',type=str,
                                     help='Router name created in controller')

def check_root_permissions():
    """
    Check to see if this is running as root privileges & exit if not.

    """
    if os.geteuid() >= 1:
        logging.error("This script must be run with elevated privileges, "
                      "please use 'sudo -E' or run as root")
        sys.exit(1)

def check_env_vars(args, parser):
    """
    Sets argparse argument values based on environment variables with matching names.

    :args:args (argparse.Namespace): A Namespace object containing the parsed arguments.

    """
    for arg in vars(args):
        env_name = arg.upper()
        env_value = os.environ.get(env_name)
        if env_value is not None:
            current_argument = getattr(args, arg)
            if current_argument == parser.get_default(arg) or current_argument is None:
                if ',' in env_value:
                    value = env_value.split(',')
                else:
                    value = env_value
                setattr(args, arg, value)
            else:
                logging.warning("Overriding Environmental value"
                                " for %s, with value set via cli", arg)

def check_parameters_file(args, parser):
    """
    Sets argparse argument values based on values in a YAML or JSON file.

    :args:args (argparse.Namespace): A Namespace object containing the parsed arguments.

    """
    if not os.path.exists(args.parametersFile):
        logging.error("Unable to open file: %s", args.parametersFile)
        sys.exit(1)

    logging.debug("Attempting to open parameters file: %s", args.parametersFile)
    with open(args.parametersFile, encoding='UTF-8') as open_file:
        if args.parametersFile.endswith('.json'):
            logging.debug("Found json file, trying to open.")
            try:
                config = json.load(open_file)
            except json.JSONDecodeError as error:
                logging.error("Unable to decode Json file: %s", error)
                sys.exit(1)
        elif args.parametersFile.endswith('.yaml') or args.parametersFile.endswith('.yml'):
            logging.debug("Found yaml file, trying to open.")
            try:
                config = yaml.safe_load(open_file)
            except yaml.YAMLError as error:
                logging.error("Unable to decode Yaml file: %s", error)
                sys.exit(1)
        else:
            logging.error("File format not supported: %s", args.parametersFile)
            sys.exit(1)

    for arg in vars(args):
        if arg in config:
            current_argument = getattr(args, arg)
            if current_argument == parser.get_default(arg) or current_argument is None:
                setattr(args, arg, config[arg])
            else:
                logging.warning("Overriding parameter file value for %s,"
                                " with value set via cli", arg)

def create_file(name, path, content="", permissions=0o644):
    """
    Create a file with the given name, path, content, and permissions.

    :param:name (str): The name of the file to create.
    :param:path (str): The path where the file should be created.
    :param:content (str, optional): The content to be written to the file. Defaults to empty string.
    :param:permissions (int, optional): The file permissions in octal notation. Defaults to 0o644.

    :return:str: The full path of the created file.
    :return:None: If there was an error creating the file.
    """
    try:
        logging.debug("Writing file %s", name)
        full_name_path = os.path.join(path, name)

        with open(full_name_path, "w", encoding='UTF-8') as file:
            file.write(content)

        logging.debug("Updating permissions of file: %s", name)
        os.chmod(full_name_path, permissions)

    except OSError as error:
        logging.error("Writing file to disk: %s", error)
        sys.exit(1)

    return full_name_path

def create_edge_router(session_token, router_name, endpoint, enable_tunneler):
    """
    Creates a new edge router using the session token.

    :param session_token: The session token.
    :param router_name: The name of the new edge router.
    :param endpoint: The scheme, hostname or IP and port of the controller.
    :return: The created edge router id.
    """
    url = f"{endpoint}/edge/management/v1/edge-routers"
    headers = {
        "Content-Type": "application/json",
        "zt-session": session_token
    }
    payload = {
        "name": router_name,
        'isTunnelerEnabled': enable_tunneler
    }
    logging.debug("TunnelerEnabled: %s", enable_tunneler)
    urllib3.disable_warnings()
    try:
        response = requests.post(url, headers=headers,
                                json=payload,
                                timeout=15,
                                verify=False)
    except requests.ConnectTimeout:
        logging.error("Unable to connect to controller: Connection Timed out")
        sys.exit(1)
    except requests.ConnectionError:
        logging.error("Unable to connect to controller: Connection Error")

    if response.status_code == 201:
        return response.json()['data']['id']
    if "name is must be unique" in response.text:
        logging.error("A router by the name: '%s' already exists.", router_name)
    else:
        logging.error("Unable to create router: %s %s",
                        response.status_code,
                        response.text)
    sys.exit(1)

def create_parser():
    """
    Create argparser Namespace

    :return: A Namespace containing arguments
    """
    __version__ = '1.0.0'
    parser = argparse.ArgumentParser()

    add_general_arguments(parser, __version__)
    add_install_arguments(parser)
    add_router_identity_arguments(parser)
    add_router_ctrl_arguments(parser)
    add_router_health_checks_arguments(parser)
    add_router_metrics_arguments(parser)
    add_router_edge_arguments(parser)
    add_router_api_proxy_arguments(parser)
    add_router_fabric_link_arguments(parser)
    add_router_listener_arguments(parser)
    add_router_web_arguments(parser)
    add_create_router_arguments(parser)

    return parser

def compare_semver(version1, version2):
    """
    Compare two semantic version numbers.

    :param version1: The first version number as a string.
    :param version2: The second version number as a string.
    :return: 1 if version1 is greater, -1 if version2 is greater, 0 if equal.
    """
    version_one = Version(version1)
    version_two = Version(version2)

    if version_one > version_two:
        return 1
    if version_one < version_two:
        return -1
    return 0

def decode_jwt(jwt_string):
    """
    Process a jwt passed in as a string.
    Read the JWT & check if it's not expired, and returns the decoded payload
    as a dictionary or exit with error if expired.

    :param args: An object containing either the enrollment_jwt or jwt_file attribute.
    :return: The decoded JWT payload as a dictionary if the JWT is not expired.
    """
    try:
        jwt_decoded = jwt.decode(jwt_string, options={"verify_signature": False})
    except jwt.DecodeError:
        logging.error("Unable to decode JWT")
        sys.exit(1)
    current_time = time.time()
    if jwt_decoded['exp'] < current_time:
        logging.error("JWT is expired")
        sys.exit(1)
    return jwt_decoded, jwt_string

def download_file(download_url):
    """
    Download a file from the specified URL and save it locally as 'download_{timestamp}.tar.gz'.

    :param download_url: The URL of the file to download.
    :return: The name of the downloaded file.
    """
    try:
        logging.info("Downloading file: %s", download_url)
        timestamp = int(time.time())
        file_name=f"download_{timestamp}.tar.gz"
        response = requests.get(download_url, stream=True, timeout=120)

        if response.status_code == 200:
            total_size = int(response.headers.get("content-length", 0))
            block_size = 1024  # 1 Kibibyte
            status_bar = tqdm(total=total_size, unit="iB", unit_scale=True, desc="Downloading")

            with open(file_name, "wb") as open_file:
                for data in response.iter_content(block_size):
                    status_bar.update(len(data))
                    open_file.write(data)
            status_bar.close()
            logging.info("Successfully downloaded file")
        elif response.status_code == 404:
            logging.error("File not found at the specified URL")
            sys.exit(1)
        else:
            logging.error("Unexpected status code: %s", response.status_code)
            sys.exit(1)
    except OSError:
        logging.error("Unable to download binaries")
        sys.exit(1)
    return file_name

def enroll_ziti(jwt_string, install_dir):
    """
    Register the ziti edge router
    This function should be updated once Ziti has fix the exit codes.
    """
    logging.info("Starting Router Enrollment")
    # write jwt file
    logging.debug("Attempting to write jwt file to disk")

    jwt_path = create_file(name="enroll.jwt",
                           path=install_dir,
                           content=jwt_string)

    if os.path.isfile(f"{install_dir}/ziti-router"):
        registration_command = [f"{install_dir}/ziti-router",
                                'enroll',
                                f"{install_dir}/config.yml",
                                '--jwt',
                                jwt_path]
    else:
        registration_command = [f"{install_dir}/ziti",
                                'router',
                                'enroll',
                                f"{install_dir}/config.yml",
                                '--jwt',
                                jwt_path]

    try:
        subprocess.run(registration_command,
                       capture_output=True,
                       text=True,
                       check=True)
    except subprocess.CalledProcessError as error:
        if "registration complete" in error.stderr:
            logging.info("Successfully enrolled Ziti")
            create_file(name=".is_registered",
                        path=install_dir)
        else:
            logging.error("Failed to register Ziti"
                          "Command output %s %s", error.stdout, error.stderr)
            sys.exit(1)
    logging.info("Successfully enrolled Ziti")
    create_file(name=".is_registered",
                path=install_dir)

def get_default_interface():
    """
    Get the name of the network interface associated with the default gateway.

    :return:str: The name of the network interface associated with the default gateway.
    :return:None: Returns None if no default gateway or associated interface is found.
    """
    try:
        route_output = subprocess.check_output(["ip",
                                                "route",
                                                "show",
                                                "default"]).decode("utf-8").strip()
        default_gateway_interface = route_output.split(" ")[4]
    except (subprocess.CalledProcessError, IndexError):
        return None

    return default_gateway_interface

def get_hostname_from_ip(ip_address, args):
    """
    Get the hostname associated with an IP address.

    :param: ip (str): The IP address to look up.
    :param args: Parsed command line arguments.

    :return:str: The hostname associated with the IP address.
    :return:None: If the IP address is invalid or the hostname cannot be found.
    """
    if args.noHostname:
        return None
    if not is_valid_ip(ip_address):
        logging.error("Provided IP is not an ip: %s", ip_address)
        return None

    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        logging.debug("Unable to find the hostname for IP address %s", ip_address)
        return None

def get_router_jwt(session_token, router_id, endpoint):
    """
    Authenticates with the given token and retrieves a router jwt.

    :param session_token: The session token.
    :param routerId: The id of the edge router use to retrive the jwt.
    :param endpoint: The scheme, hostname or IP and port of the controller.
    :return: The session token.
    """

    url = f"{endpoint}/edge/management/v1/edge-routers/{router_id}"
    headers = {
        "Content-Type": "application/json",
        "zt-session": session_token
    }
    logging.debug("Attempting to acces url: %s", url)

    urllib3.disable_warnings()
    try:
        response = requests.get(url, headers=headers, timeout=15, verify=False)
    except requests.ConnectTimeout:
        logging.error("Unable to connect to controller: Connection Timed out")
        sys.exit(1)
    except requests.ConnectionError:
        logging.error("Unable to connect to controller: Connection Error")
        sys.exit(1)

    if response.status_code == 200:
        logging.debug("Edge Router JWT: %s", response.json()['data']['enrollmentJwt'])
        return response.json()['data']['enrollmentJwt']
    logging.error("Unable to retrieve jwt from edge router: %s %s",
                    response.status_code,
                    response.text)
    sys.exit(1)

def get_os_platform():
    """
    Determines the OS platform and returns one of the following:
    'darwin-amd64', 'linux-arm', 'linux-arm64', 'linux-amd64', 'windows-amd64'

    :return: The OS platform string.
    """
    os_system = platform.system().lower()
    architecture = platform.machine().lower()

    if os_system == 'darwin':
        return 'darwin-amd64'
    if os_system == 'linux':
        if architecture == 'arm' or architecture.startswith('armv'):
            return 'linux-arm'
        if architecture in ('aarch64','arm64'):
            return 'linux-arm64'
        if architecture == 'x86_64':
            return 'linux-amd64'
        logging.error("Unsupported Linux architecture: %s", architecture)
        sys.exit(1)
    if os_system == 'windows':
        if architecture in ('amd64','x86_64'):
            return 'windows-amd64'
        logging.error("Unsupported Linux architecture: %s", architecture)
        sys.exit(1)
    logging.error("Unsupported OS/architecture: %s %s", os_system, architecture)
    sys.exit(1)

def get_session_token(username, password, endpoint):
    """
    Authenticates with the given username and password and retrieves a session token.

    :param username: The username for authentication.
    :param password: The password for authentication.
    :param endpoint: The scheme, hostname or IP and port of the controller.
    :return: The session token.
    """

    url = f"{endpoint}/edge/v1/authenticate?method=password"
    logging.debug("Attempting to acces url: %s", url)
    payload = {
        "username": username,
        "password": password
    }

    urllib3.disable_warnings()
    try:
        response = requests.post(url, json=payload, timeout=15, verify=False)
    except requests.ConnectTimeout:
        logging.error("Unable to connect to controller: Connection Timed out")
        sys.exit(1)
    except requests.ConnectionError:
        logging.error("Unable to connect to controller: Connection Error")
        sys.exit(1)

    if response.status_code == 200:
        logging.debug("Session Token: %s", response.json()['data']['token'])
        return response.json()['data']['token']
    logging.error("Unable to authenticate with controller: %s %s",
                    response.status_code,
                    response.text)
    sys.exit(1)

def get_private_address():
    """
    Get the local IP address of the network interface associated with the default gateway.

    :return:str: The local IP address of the network interface associated with the default gateway.
    :return:None: Returns None if no default gw, associated interface, or local IP address is found.
    """
    default_interface = get_default_interface()

    if default_interface is None:
        return None

    for info in psutil.net_if_addrs()[default_interface]:
        if info.family == socket.AF_INET:
            logging.debug("Found address of interface: %s", info.address)
            return info.address

    return None

def get_public_address():
    """
    Get the public IP address of the machine.

    :return:str: The public IP address of the machine. Returns None if an error occurs.
    """
    try:
        response = requests.get("https://api.ipify.org", timeout=15)
        response.raise_for_status()
        return response.text
    except requests.ConnectTimeout:
        logging.warning("Unable to get external ip: Connection Timed out")
        return None
    except requests.ConnectionError:
        logging.warning("Unable to get external ip: Connection Error")
        return None
    except requests.RequestException:
        return None

def get_ziti_controller_version(controller_url):
    """
    Retrieve the Ziti controller version from the given URL.

    :param controller_url: The URL of the Ziti controller.
    :return: The version of the Ziti controller as a string.
    :raises ValueError: If unable to parse the response or communicate with the controller.
    """
    try:
        logging.info("Version not specified, going to check with controller")
        endpoint_url = f"{controller_url}/edge/v1/version"
        logging.debug("Attempting to access %s", endpoint_url)

        urllib3.disable_warnings()
        try:
            response = requests.get(endpoint_url, verify=False, timeout=15)
            response.raise_for_status()
        except requests.ConnectTimeout:
            logging.error("Unable to get controller version: Connection Timed out")
            sys.exit(1)
        except requests.ConnectionError:
            logging.error("Unable to get controller version: Connection Error")
            sys.exit(1)

        try:
            result = json.loads(response.text)
            version = result['data']['version'].split("v")[1]
            logging.info("Found version %s", version)
            return version
        except (json.decoder.JSONDecodeError, KeyError):
            logging.error("Unable to parse response from server")
            sys.exit(1)

    except requests.exceptions.RequestException:
        logging.error("Unable to communicate with controller")
        sys.exit(1)

def handle_dns(args):
    """
    Configure DNS settings for Ziti based on the current operating system.

    This function currently supports Ubuntu, Centos, Redhat.
    It delegates the configuration to a dedicated function for
    the specific operating system.

    :param args: A Namespace object containing the parsed command-line arguments,
                 which will be passed to the appropriate OS-specific function.
    """
    os_name = distro.id()

    if os_name == 'ubuntu':
        logging.info("Starting Ubuntu DNS setup")
        handle_ubuntu_dns(args)
    # TODO: Add other dns handlers for centos redhat debian
    else:
        logging.info("Unable to handle DNS setup on this distro, "
                     "please ensure the local host is the first resolver")

def handle_ubuntu_dns(args):
    """
    Configure Ubuntu DNS settings for Ziti by creating a resolved configuration file
    and restarting the necessary network services.

    :param args: A Namespace object containing the parsed command-line arguments,
                 specifically looking for the `tunnelListener` argument.
    """
    if not os.path.exists("/usr/lib/systemd/resolved.conf.d"):
        try:
            os.makedirs("/usr/lib/systemd/resolved.conf.d")
        except OSError:
            logging.error("Unable to create resolve directories")
            sys.exit(1)
    if args.tunnelListener:
        default_address = urlparse(args.tunnelListener[1]).hostname
    else:
        default_address = get_private_address()
    resolved_content = "#Ziti Added file\n[Resolve]\nDNS=" + default_address + "\n"
    try:
        create_file(name="01-ziti.conf",
                    path="/usr/lib/systemd/resolved.conf.d/",
                    content=resolved_content)
    except OSError:
        logging.error("Unable to write dns configuration")
        sys.exit(1)
    logging.debug("Restarting network service to apply dns changes")
    manage_systemd_service('systemd-networkd', 'restart')
    manage_systemd_service('systemd-resolved', 'restart')

def handle_systemd_setup(install_version, install_dir):
    """
    Create a systemd service unit file for the Ziti router based on the installed version.

    This function takes the installed version and the installation directory as input,
    generates the systemd service unit content using a Jinja2 template, and creates
    the systemd service unit file in the /etc/systemd/system/ directory.

    :param install_version: The installed version of the Ziti router as a string (e.g., '0.27.0').
    :param install_dir: The install directory for the Ziti router as a string (e.g., '/opt/ziti/').
    """
    service_template = Template(SYSTEMD_UNIT_TEMPLATE_STRING)
    logging.info("Installing service unit file")
    version_compare = compare_semver(install_version, '0.27.0')
    logging.debug("Version comp value: %s",version_compare)
    single_binary = False
    if version_compare >= 0:
        single_binary = True
    service_unit = service_template.render(single_binary=single_binary,
                                           install_dir=install_dir)
    deamon_reload = False
    if os.path.isfile("/etc/systemd/system/ziti-router.service"):
        deamon_reload = True
    create_file(name="ziti-router.service",
                path="/etc/systemd/system/",
                content=service_unit)
    if deamon_reload:
        manage_systemd_service('ziti-router', 'daemon-reload')

def handle_ziti_install(controller_info,
                        download_url=None,
                        install_version=None,
                        install_dir=None):
    """
    Handle the download and installation of Ziti binaries.

    :param controller_info: A dictionary containing controller URL components:
                            {'scheme': str, 'hostname': str, 'port': int}
    :param download_url: The URL to download the Ziti binaries from (optional).
    :param install_version: The version of Ziti binaries to install (optional).
    :param install_dir: The path to install the Ziti binaries (optional).
    """
    #reasseble the controller url
    controller_url = (
    f"{controller_info['scheme']}://"
    f"{controller_info['hostname']}:"
    f"{controller_info['mgmt_port']}")
    if install_version is None:
        install_version = get_ziti_controller_version(controller_url)
    else:
        logging.info("Version was specified: %s", install_version)
    if download_url is None:
        os_architecture = get_os_platform()
        download_uri = ('https://github.com/openziti/ziti/releases/download/v' +
                        str(install_version) +
                        '/ziti-' +
                        os_architecture +
                        '-' +
                        str(install_version) +
                        '.tar.gz')
    else:
        download_uri = download_url
    downloaded_file = download_file(download_uri)
    install_ziti_binaries(downloaded_file, install_dir)
    handle_systemd_setup(install_version, install_dir)

def install_ziti_binaries(file_to_extract, install_dir):
    """
    Install Ziti binaries from the specified tar file to the target directory.

    :param file_name: The path to the tar file containing Ziti binaries.
    :param install_dir: The directory where the Ziti binaries should be installed.
    :raises OSError: If there is an error creating the install directory or extracting the binaries.
    """
    logging.info("Starting binary install")
    try:
        logging.debug("Attempting to create diretory: %s", f'{install_dir}/certs')
        if not os.path.isdir(f'{install_dir}/certs'):
            os.makedirs(f'{install_dir}/certs', exist_ok=True)
            logging.debug("Successfully created directory")
    except OSError:
        logging.error("Unable to create install dir")
        sys.exit(1)

    try:
        logging.debug("Attempting to open tar file %s", file_to_extract)
        with tarfile.open(file_to_extract) as downloaded_file:
            for member in downloaded_file.getmembers():
                if member.name in ['ziti/ziti','ziti/ziti-router']:
                    file_name = os.path.basename(member.name)
                    logging.debug("Found member: %s", file_name)
                    destination_path = os.path.join(install_dir, file_name)
                    logging.debug("Writing file to: %s", destination_path)
                    # Extract the file with the modified path
                    with open(destination_path, "wb") as file_out:
                        extracted_file = downloaded_file.extractfile(member)
                        file_out.write(extracted_file.read())
                    os.chmod(destination_path, member.mode)
        logging.debug("Sucessfully extracted file")
        os.remove(file_to_extract)
        logging.debug("Removed file %s", file_to_extract)
    except OSError as error:
        logging.error("Unable to Extract binaries %s", error)
        sys.exit(1)

def is_valid_ip(ip_address):
    """
    Check if a given string is a valid IP address.
    """
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def manage_systemd_service(service_name, action):
    """
    Start, stop, or restart a systemd service using the systemctl command.

    :param service_name: The name of the systemd service to manage (e.g., 'ziti-router.service').
    :param action: The action to perform on the service, either 'start', 'stop', or 'restart'.
    :raises ValueError: If an invalid action is provided.
    """

    if action not in ['start', 'stop', 'restart', 'enable', 'disable', 'daemon-reload']:
        raise ValueError("Invalid action. Must be 'start',"
                         " 'stop', 'restart' or 'enable', or 'disable'.")

    if action == 'daemon-reload':
        subprocess.run(['systemctl', action], check=True)
        logging.info("Service %s %s successful.", service_name, action)
    else:
        try:
            subprocess.run(['systemctl', action, service_name], check=True)
            logging.info("Service %s %s successful.", service_name, action)
        except subprocess.CalledProcessError as error:
            logging.debug("Failed to %s the %s service. Error: %s", action, service_name, error)

def set_identity(args):
    """
    Set the 'identity' field in the template_vars dictionary.

    :param args: Parsed command line arguments.
    :return: A dictionary containing the 'identity' field values.
    """

    if args.identityCert:
        identity_cert = args.identityCert
    else:
        identity_cert = f"{args.installDir}/certs/cert.pem"

    if args.identityServerCert:
        identity_server_cert = args.identityServerCert
    else:
        identity_server_cert = f"{args.installDir}/certs/server_cert.pem"

    if args.identityKey:
        identity_key = args.identityKey
    else:
        identity_key = f"{args.installDir}/certs/key.pem"

    if args.identityCa:
        identity_ca = args.identityCa
    else:
        identity_ca = f"{args.installDir}/certs/ca.pem"

    return {
        'cert': identity_cert,
        'server_cert': identity_server_cert,
        'key': identity_key,
        'ca': identity_ca
    }

def set_ctrl(args, controller_info):
    """
    Set the 'ctrl' field in the template_vars dictionary.

    :param args: Parsed command line arguments.
    :controller
    :return: A dictionary containing the 'ctrl' field values.
    """
    if controller_info:
        return {'endpoint': f"tls:{controller_info['hostname']}:{controller_info['fabric_port']}"}
    return {'endpoint': args.controller}

def set_link_dialers(args):
    """
    Set the 'link_dialers' field in the template_vars dictionary.

    :param args: Parsed command line arguments.
    :return: A list containing the 'link_dialers' field values.
    """
    link_dialers = []
    if args.linkDialers:
        for dialer in args.linkDialers:
            link_dialer_values = {}
            link_dialer_values['binding'] = dialer[0]
            if len(dialer) > 1:
                link_dialer_values['bind'] = dialer[1]
            link_dialers.append(link_dialer_values)
    else:
        link_dialer_values = {'binding': 'transport'}
        link_dialers.append(link_dialer_values)
    return link_dialers

def set_link_listeners(args):
    """
    Set the 'link_listeners' field in the template_vars dictionary.

    :param args: Parsed command line arguments.
    :return: A list containing the 'link_listeners' field values.
    """
    link_listeners = []
    if args.linkListeners:
        for listener in args.linkListeners:
            link_listener_values = {'binding': listener[0],
                                    'bind': listener[1],
                                    'advertise': listener[2]}
            link_listener_options_value = {'outqueuesize': listener[3]}
            link_listener_values['options'] = link_listener_options_value
            link_listeners.append(link_listener_values)
    elif args.assumePublic:
        public_address = get_public_address()
        hostname = get_hostname_from_ip(public_address, args)
        if hostname is None:
            advertise_value = public_address
        else:
            advertise_value = hostname
        link_listener_values = {'binding': 'transport',
                                'bind': 'tls:0.0.0.0:80',
                                'advertise': f"tls:{advertise_value}:80"}
        link_listener_options_value = {'outqueuesize': '16'}
        link_listener_values['options'] = link_listener_options_value
        link_listeners.append(link_listener_values)

    return link_listeners

    #return args.linkListeners if args.linkListeners else []

def set_health_checks(args):
    """
    Set the 'healthChecks' field in the template_vars dictionary.

    :param args: Parsed command line arguments.
    :return: A dictionary containing the 'healthChecks' field values, or None if not applicable.
    """
    return {
        'ctrlPingCheck': {
            'interval': f"{args.ctrlPingCheckInterval}s",
            'timeout': f"{args.ctrlPingCheckTimeout}s",
            'initialDelay': f"{args.ctrlPingCheckInitialDelay}s"
        }
    }

def set_metrics(args):
    """
    Set the 'metrics' field in the template_vars dictionary.

    :param args: Parsed command line arguments.
    :return: A dictionary containing the 'metrics' field values, or None if not applicable.
    """
    if args.reportInterval or args.messageQueueSize:
        return {
            'reportInterval': f"{args.reportInterval}s",
            'messageQueueSize': args.messageQueueSize
        }
    return None

def set_edge(args):
    """
    Set the 'edge' field in the template_vars dictionary.

    :param args: Parsed command line arguments.
    :return: A dictionary containing the 'edge' field values.
    """
    edge = {}
    if args.disableEdge:
        edge['heartbeatIntervalSeconds'] = args.heartbeatIntervalSeconds
        edge['csr'] = {
            'country': args.csrCountry,
            'province': args.csrProvince,
            'locality': args.csrLocality,
            'organization': args.csrOrganization,
            'organizationalUnit': args.csrOrganizationalUnit,
            'sans': set_edge_csr_sans(args)
        }
        if args.apiProxyListener or args.apiProxyUpstream:
            edge['apiProxy'] = {
                'listener': args.apiProxyListener,
                'upstream': args.apiProxyUpstream
            }
    return edge

def assemble_sans(args, csr_sans_dns, csr_sans_ip):
    """
    Assemble the 'sans' field values into a dictionary.

    :param args: Parsed command line arguments.
    :param csr_sans_dns: A list of DNS values for the 'sans' field.
    :param csr_sans_ip: A list of IP values for the 'sans' field.
    :return: A dictionary containing the 'sans' field values.
    """
    sans = {"dns": csr_sans_dns, "ip": csr_sans_ip}

    if args.csrSansEmail:
        csr_sans_email = []
        if not isinstance(args.csrSansEmail, list):
            csr_emails = [args.csrSansEmail]
        else:
            csr_emails = args.csrSansEmail
        for item in csr_emails:
            csr_sans_email.append(item)
        sans['email'] = csr_sans_email

    if args.csrSansUri:
        csr_sans_uri = []
        if not isinstance(args.csrSansUri, list):
            csr_uri = [args.csrSansUri]
        else:
            csr_uri = args.csrSansUri
        for item in csr_uri:
            csr_sans_uri.append(item)
        sans['uri'] = csr_sans_uri

    return sans

def set_controller_info(args, jwt_info):
    """
    Extract the controller information from the JWT and command line arguments.

    :param args: An object containing the command line arguments.
    :param jwt_info: A dictionary containing the decoded JWT information.
    :return: A dictionary of the controller information.
    """
    controller_url = urlparse(jwt_info['iss'])

    if args.controller:
        controller_hostname = args.controller
    else:
        controller_hostname = controller_url.hostname

    controller_info = {
        "scheme": controller_url.scheme,
        "hostname": controller_hostname,
        "mgmt_port": controller_url.port,
        "fabric_port": args.controllerFabricPort
    }

    return controller_info

def set_edge_csr_sans(args):
    """
    Set the 'sans' field in the 'edge' -> 'csr' section of the template_vars dictionary.

    :param args: Parsed command line arguments.
    :return: A dictionary containing the 'sans' field values.
    """
    csr_sans_dns, csr_sans_ip = process_listeners_sans(args)

    if args.csrSansIp:
        if not isinstance(args.csrSansIp, list):
            csr_ip = [args.csrSansIp]
        else:
            csr_ip = args.csrSansIp
        for item in csr_ip:
            csr_sans_ip.append(item)
    if args.csrSansDns:
        if not isinstance(args.csrSansDns, list):
            csr_dns = [args.csrSansDns]
        else:
            csr_dns = args.csrSansDns
        for item in csr_dns:
            csr_sans_dns.append(item)

    sans = assemble_sans(args, csr_sans_dns, csr_sans_ip)

    logging.debug(sans)
    return sans

def set_listeners(args):
    """
    Set the 'listeners' field in the template_vars dictionary.

    :param args: Parsed command line arguments.
    :return: A list containing the 'listeners' field values.
    """
    listeners = []
    listeners.extend(process_edge_listeners(args))
    listeners.extend(process_proxy_listeners(args))
    listeners.extend(process_tunnel_listeners(args))
    return listeners

def set_api_proxy(args):
    """
    Set the 'apiProxy' field in the 'edge' section of the template_vars dictionary.

    :param args: Parsed command line arguments.
    :return: A dictionary containing the 'apiProxy' field values, or None if not applicable.
    """
    api_proxy = {
        'listener': args.apiProxyListener,
        'upstream': args.apiProxyUpstream
    }
    return api_proxy

def set_webs(args):
    """
    Set the 'webs' field in the template_vars dictionary.

    :param args: Parsed command line arguments.
    :return: A list containing the 'web' field values, or None if not applicable.
    """
    webs = []
    if args.webs:
        for web in args.webs:
            web_values = {'name': web[0]}
            web_bindpoints_values = {'interface':web[1],'address': web[2]}
            web_values['bindpoints'] = web_bindpoints_values
            web_apis_values = {'binding': web[3]}
            web_values['apis'] = web_apis_values
            webs.append(web_values)
    else:
        web_values = {'name': 'health-check'}
        web_bindpoints_values = {'interface':'0.0.0.0:8081','address': '0.0.0.0:8081'}
        web_values['bindpoints'] = web_bindpoints_values
        web_apis_values = {'binding': 'health-checks'}
        web_values['apis'] = web_apis_values
        webs.append(web_values)
    return webs

def setup_logging(logfile, loglevel=logging.INFO):
    """
    Set up logging to log messages to both the console and a file.

    :param logfile: The file to log messages to. Defaults to 'program_name.log'.
    :param loglevel: The minimum level of log messages to display. Defaults to logging.INFO.
    """
    class CustomFormatter(logging.Formatter):
        """
        Return a custom color for the message if the level is higher then warning.
        """
        def format(self, record):
            if record.levelno == logging.WARNING:
                level_color = Fore.YELLOW
            elif record.levelno >= logging.ERROR:
                level_color = Fore.RED
            else:
                level_color = ""

            formatted_msg = super().format(record)
            colored_levelname = f"{level_color}{record.levelname}{Style.RESET_ALL}"
            return formatted_msg.replace(record.levelname, colored_levelname)

    # Initialize colorama
    init(autoreset=True)

    # Create a logger object
    logger = logging.getLogger()
    logger.setLevel(loglevel)

    # Create a file handler to log messages to a file
    file_handler = logging.FileHandler(logfile)
    file_handler.setLevel(loglevel)

    # Create a console handler to log messages to the console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(loglevel)

    # Create formatters with custom date and time format, and add them to the appropriate handlers
    file_formatter = CustomFormatter('%(asctime)s-%(levelname)s-%(message)s',
                                     datefmt='%Y-%m-%d-%H:%M:%S')
    file_handler.setFormatter(file_formatter)

    console_formatter_info = CustomFormatter('%(message)s')
    console_formatter_warning_error = CustomFormatter('%(levelname)s-%(message)s')

    def console_format(record):
        if record.levelno == logging.INFO:
            return console_formatter_info.format(record)
        return console_formatter_warning_error.format(record)

    console_handler.format = console_format

    # Add the handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

def process_edge_listeners(args):
    """
    Process edge listeners.

    :param args: Parsed command line arguments.
    :return: A list containing the processed edge listener values.
    """
    edge_listeners = []
    if args.edgeListeners:
        for listener in args.edgeListeners:
            listener_values, listener_options = process_edge_listener_options(listener)
            listener_values['options'] = listener_options
            edge_listeners.append(listener_values)
    else:
        if args.assumePublic:
            public_address = get_public_address()
            hostname = get_hostname_from_ip(public_address, args)
            if hostname is None:
                advertise_value = public_address
            else:
                advertise_value = hostname
        else:
            private_address = get_private_address()
            hostname = get_hostname_from_ip(private_address, args)
            if hostname is None:
                advertise_value = private_address
            else:
                advertise_value = hostname
        listener_values = {'binding': 'edge', 'address': 'tls:0.0.0.0:443'}
        listener_options = {'advertise': f'{advertise_value}:443'}
        listener_values['options'] = listener_options
        edge_listeners.append(listener_values)
    return edge_listeners

def process_edge_listener_options(listener):
    """
    Process edge listener options.

    :param listener: A tuple or list containing the edge listener options.
    :return: A tuple containing the listener_values and listener_options dictionaries.
    """
    listener_values = {'binding': 'edge', 'address': listener[0]}
    listener_options = {}
    if len(listener) > 1:
        listener_options['advertise'] = listener[1]
    if len(listener) > 2:
        listener_options['maxQueuedConnects'] = listener[2]
    if len(listener) > 3:
        listener_options['maxOutstandingConnects'] = listener[3]
    if len(listener) > 4:
        listener_options['connectTimeoutMs'] = listener[4]
    if len(listener) > 5:
        listener_options['lookupApiSessionTimeout'] = listener[5]
    return listener_values, listener_options

def process_jwt(args, parser):
    """
    Process the JWT by either finding it as a positional parameter, file or
    by adding enough information to connect to the controller to create one.

    :param args: An object containing either the enrollment_jwt, jwt_file attributes
                 or Router Creation attributes.
    :param parser: The argparse.ArgumentParser to print out help if attributes were not passed.
    :return: The decoded JWT string.
    """
    if args.enrollment_jwt:
        logging.debug("JWT String: %s", args.enrollment_jwt)
        jwt_info, jwt_string = decode_jwt(args.enrollment_jwt)
    elif args.jwt:
        with open(args.jwt, 'r',encoding='UTF-8') as file:
            jwt_string = file.read().strip()
        jwt_info, jwt_string = decode_jwt(jwt_string)
    elif (args.controller and
          args.controllerMgmtPort and
          args.adminUser and
          args.adminPassword and
          args.routerName):
        controller_url = (f"https://{args.controller}:{args.controllerMgmtPort}")
        session_token = get_session_token(args.adminUser,
                                          args.adminPassword,
                                          controller_url)
        router_id = create_edge_router(session_token,
                                       args.routerName,
                                       controller_url,
                                       tunneler_enabled(args))
        router_jwt = get_router_jwt(session_token,
                                    router_id,
                                    controller_url)
        logging.info("Writing jwt file: %s_enrollment.jwt", args.routerName)
        create_file(f"{args.routerName}_enrollment.jwt",".", router_jwt)
        jwt_info, jwt_string = decode_jwt(router_jwt)
    else:
        parser.print_help()
        logging.error("Need a JWT or Router Creation and Controller Options")
        sys.exit(1)

    return jwt_string, jwt_info

def process_listeners_sans(args):
    """
    Process the listener information and add default values for the 'sans' field.

    :param args: Parsed command line arguments.
    :return: Two lists containing DNS and IP values for the 'sans' field.
    """
    csr_sans_dns = []
    csr_sans_ip = []

    if args.edgeListeners:
        for listener in args.edgeListeners:
            advertise_value = (listener[1]).split(":")[0]
            if is_valid_ip(advertise_value):
                csr_sans_ip.append(advertise_value)
                hostname = get_hostname_from_ip(advertise_value, args)
                if hostname is not None:
                    csr_sans_dns.append(hostname)
            else:
                csr_sans_dns.append(advertise_value)
    else:
        if args.assumePublic:
            default_ip_address = get_public_address()
        else:
            default_ip_address = get_private_address()

        csr_sans_ip.append(default_ip_address)
        default_hostname = get_hostname_from_ip(default_ip_address, args)
        if default_hostname is not None:
            csr_sans_dns.append(default_hostname)

    csr_sans_ip.append('127.0.0.1')
    csr_sans_dns.append('localhost')

    return csr_sans_dns, csr_sans_ip

def process_proxy_listeners(args):
    """
    Process proxy listeners.

    :param args: Parsed command line arguments.
    :return: A list containing the processed proxy listener values.
    """
    proxy_listeners = []
    if args.proxyListeners:
        for listener in args.proxyListeners:
            listener_values = {
                'binding': 'proxy',
                'address': listener[0],
                'service': listener[1]
            }
            proxy_listeners.append(listener_values)
    return proxy_listeners

def process_tunnel_listeners(args):
    """
    Process tunnel listeners.

    :param args: Parsed command line arguments.
    :return: A list containing the processed tunnel listener values.
    """
    tunnel_listeners = []
    if args.tunnelListener:
        listener_values, listener_options = process_tunnel_listener_options(args.tunnelListener)
        listener_values['options'] = listener_options
        tunnel_listeners.append(listener_values)
    if args.autoTunnelListener:
        listener_values, listener_options = process_tunnel_listener_options(None,
                                                                            args.autoTunnelListener)
        listener_values['options'] = listener_options
        tunnel_listeners.append(listener_values)
    return tunnel_listeners

def tunneler_enabled(args):
    """
    Check if tunneler should be enabled.

    :param args: Parsed command line arguments.
    :return: true if we need to enable tunneler on the router.
    """
    if args.tunnelListener or args.autoTunnelListener:
        return True
    return False

def process_tunnel_listener_options(listener, auto_configure=False):
    """
    Process tunnel listener options.

    :param listener: A tuple or list containing the tunnel listener options.
    :param auto_configure: Automatically add a tproxy listener
    :return: A tuple containing the listener_values and listener_options dictionaries.
    """
    listener_values = {'binding': 'tunnel'}
    listener_options = {}
    if auto_configure:
        listener_options['mode'] = 'tproxy'
        listener_options['resolver'] = f"udp://{get_private_address()}:53"
        listener_options['lanIf'] = get_default_interface()
    else:
        if len(listener) > 0:
            listener_options['mode'] = listener[0]
        if len(listener) > 1:
            listener_options['resolver'] = listener[1]
        if len(listener) > 2:
            listener_options['lanIf'] = listener[2]
    return listener_values, listener_options

def create_template(args, controller_info):
    """
    Fill out the template with the provided command line arguments and print it.

    :param args: Parsed command line arguments.
    :return: complete template
    """
    template_vars = {}

    template_vars['identity'] = set_identity(args)
    template_vars['ctrl'] = set_ctrl(args, controller_info)
    template_vars['link_dialers'] = set_link_dialers(args)
    template_vars['link_listeners'] = set_link_listeners(args)
    if args.disableHealthChecks:
        template_vars['healthChecks'] = set_health_checks(args)
    if args.disableMetrics:
        template_vars['metrics'] = set_metrics(args)
    if args.disableEdge:
        template_vars['edge'] = set_edge(args)
        template_vars['edge']['csr']['sans'] = set_edge_csr_sans(args)
    if args.apiProxyListener or args.apiProxyUpstream:
        template_vars['apiProxy'] = set_api_proxy(args)
    if args.disableListeners:
        template_vars['listeners'] = set_listeners(args)
    if args.disableHealthChecks:
        template_vars['webs'] = set_webs(args)

    template = Template(CONFIG_TEMPLATE_STRING)
    filled_out_template = template.render(template_vars)

    return filled_out_template

def main(args):
    """
    Main logic
    """
    # create parser
    parser = create_parser()

    # get arguments passed
    args = parser.parse_args(args)

    if args.logFile:
        log_file = args.logFile
    else:
        program_name = (os.path.basename(__file__)).split(".")[0]
        log_file = f"{program_name}.log"

    # setup logging only if calling from script
    if __name__ == '__main__':
        setup_logging(log_file, args.logLevel)

    # check environment for args
    check_env_vars(args, parser)

    # check file for args if a file is passed in
    if args.parametersFile:
        check_parameters_file(args, parser)

    # root check
    check_root_permissions()

    # check to make sure it's not already registered
    if args.force:
        if os.path.isfile(f"{args.installDir}/.is_registered"):
            logging.error("Already registered. Override with -f/--force")
            sys.exit(1)
    else:
        manage_systemd_service('ziti-router.service','stop')

    # print template
    if args.printTemplate:
        print(CONFIG_TEMPLATE_STRING)
        sys.exit(0)

    # check for jwt & extract info
    jwt_string, jwt_info  = process_jwt(args, parser)

    # set up controller info
    controller_info = set_controller_info(args, jwt_info)

    # create config
    config = create_template(args, controller_info)

    # print config
    if args.printConfig:
        print(config)
        sys.exit(0)

    # set up local dns for tunnel mode
    if args.tunnelListener or args.autoTunnelListener:
        handle_dns(args)

    # download extract binaries
    handle_ziti_install(controller_info,
                        args.downloadUrl,
                        args.installVersion,
                        args.installDir)

    # write config
    logging.info("Creating config file")
    create_file(name='config.yml', path=args.installDir, content=config)

    # do enrollment
    enroll_ziti(jwt_string, args.installDir)

    # start ziti
    manage_systemd_service('ziti-router.service', 'start')
    manage_systemd_service('ziti-router.service', 'enable')

# main
if __name__ == '__main__':
    main(sys.argv[1:])
