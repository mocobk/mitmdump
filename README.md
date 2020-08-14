## mitmdump
![](https://shields.mitmproxy.org/pypi/v/mitmdump.svg)
![](https://shields.mitmproxy.org/pypi/pyversions/mitmproxy.svg)

mitmdump 是对 mitmproxy 的简单封装，可以实现以编程的方式运行 mitmproxy 服务, 当然原来的命令行方式运行也是支持的。

`pip install mitmdump`

**Before:** `mitmdump -s youscript.py`

**After:** `python youscript.py` or `mitmdump -s youscript.py`

```python
from mitmproxy.http import HTTPFlow

from mitmdump import DumpMaster, Options


class AddHeader:
    def __init__(self):
        self.num = 0

    def response(self, flow: HTTPFlow):
        self.num = self.num + 1
        flow.response.headers["count"] = str(self.num)


addons = [
    AddHeader()
]

if __name__ == '__main__':
    opts = Options(server=True, listen_host='0.0.0.0', listen_port=8080, termlog_verbosity='info',
                   show_clientconnect_log=False, flow_detail=1, dumper_filter='~m GET')
    m = DumpMaster(opts)

    m.addons.add(*addons)
    m.run()
```

## 参数列表
mitmdump 库所有可用的参数都保持跟 mitmproxy 一致，所以你不必担心使用上的困难，以下列举了可用参数及类型，参数使用说明参考命令行中的帮助信息。

| params                              | default      | type                          |
| ----------------------------------- | ------------ | ----------------------------- |
| add_upstream_certs_to_client_chain  | False        | [<class 'bool'>]              |
| allow_hosts                         | []           | [typing.Sequence[str]]        |
| anticache                           | False        | [<class 'bool'>]              |
| anticomp                            | False        | [<class 'bool'>]              |
| block_global                        | True         | [<class 'bool'>]              |
| block_private                       | False        | [<class 'bool'>]              |
| body_size_limit                     | None         | [typing.Union[str, NoneType]] |
| certs                               | []           | [typing.Sequence[str]]        |
| ciphers_client                      | None         | [typing.Union[str, NoneType]] |
| ciphers_server                      | None         | [typing.Union[str, NoneType]] |
| client_certs                        | None         | [typing.Union[str, NoneType]] |
| client_replay                       | []           | [typing.Sequence[str]]        |
| command_history                     | True         | [<class 'bool'>]              |
| confdir                             | ~/.mitmproxy | [<class 'str'>]               |
| content_view_lines_cutoff           | 512          | [<class 'int'>]               |
| dumper_default_contentview          | auto         | [<class 'str'>]               |
| dumper_filter                       | None         | [typing.Union[str, NoneType]] |
| flow_detail                         | 1            | [<class 'int'>]               |
| http2                               | True         | [<class 'bool'>]              |
| http2_priority                      | False        | [<class 'bool'>]              |
| ignore_hosts                        | []           | [typing.Sequence[str]]        |
| keep_host_header                    | False        | [<class 'bool'>]              |
| keepserving                         | False        | [<class 'bool'>]              |
| key_size                            | 2048         | [<class 'int'>]               |
| listen_host                         | 0.0.0.0      | [<class 'str'>]               |
| listen_port                         | 8080         | [<class 'int'>]               |
| map_local                           | []           | [typing.Sequence[str]]        |
| map_remote                          | []           | [typing.Sequence[str]]        |
| mode                                | regular      | [<class 'str'>]               |
| modify_body                         | []           | [typing.Sequence[str]]        |
| modify_headers                      | []           | [typing.Sequence[str]]        |
| onboarding                          | True         | [<class 'bool'>]              |
| onboarding_host                     | mitm.it      | [<class 'str'>]               |
| onboarding_port                     | 80           | [<class 'int'>]               |
| proxyauth                           | None         | [typing.Union[str, NoneType]] |
| rawtcp                              | False        | [<class 'bool'>]              |
| readfile_filter                     | None         | [typing.Union[str, NoneType]] |
| rfile                               | None         | [typing.Union[str, NoneType]] |
| save_stream_file                    | None         | [typing.Union[str, NoneType]] |
| save_stream_filter                  | None         | [typing.Union[str, NoneType]] |
| scripts                             | []           | [typing.Sequence[str]]        |
| server                              | True         | [<class 'bool'>]              |
| server_replay                       | []           | [typing.Sequence[str]]        |
| server_replay_ignore_content        | False        | [<class 'bool'>]              |
| server_replay_ignore_host           | False        | [<class 'bool'>]              |
| server_replay_ignore_params         | []           | [typing.Sequence[str]]        |
| server_replay_ignore_payload_params | []           | [typing.Sequence[str]]        |
| server_replay_ignore_port           | False        | [<class 'bool'>]              |
| server_replay_kill_extra            | False        | [<class 'bool'>]              |
| server_replay_nopop                 | False        | [<class 'bool'>]              |
| server_replay_refresh               | True         | [<class 'bool'>]              |
| server_replay_use_headers           | []           | [typing.Sequence[str]]        |
| showhost                            | False        | [<class 'bool'>]              |
| show_clientconnect_log              | False        | [<class 'bool'>]              |
| spoof_source_address                | False        | [<class 'bool'>]              |
| ssl_insecure                        | False        | [<class 'bool'>]              |
| ssl_verify_upstream_trusted_ca      | None         | [typing.Union[str, NoneType]] |
| ssl_verify_upstream_trusted_confdir | None         | [typing.Union[str, NoneType]] |
| ssl_version_client                  | secure       | [<class 'str'>]               |
| ssl_version_server                  | secure       | [<class 'str'>]               |
| stickyauth                          | None         | [typing.Union[str, NoneType]] |
| stickycookie                        | None         | [typing.Union[str, NoneType]] |
| stream_large_bodies                 | None         | [typing.Union[str, NoneType]] |
| stream_websockets                   | False        | [<class 'bool'>]              |
| tcp_hosts                           | []           | [typing.Sequence[str]]        |
| termlog_verbosity                   | info         | [<class 'str'>]               |
| upstream_auth                       | None         | [typing.Union[str, NoneType]] |
| upstream_bind_address               |              | [<class 'str'>]               |
| upstream_cert                       | True         | [<class 'bool'>]              |
| websocket                           | True         | [<class 'bool'>]              |


### 参数作用 (参考对应的命令行参数帮助)
```bash
usage: mitmdump [options] [filter]

positional arguments:
  filter_args           Filter expression, equivalent to setting both the
                        view_filter and save_stream_filter options.

optional arguments:
  -h, --help            show this help message and exit
  --version             show version number and exit
  --options             Show all options and their default values
  --commands            Show all commands and their signatures
  --set option[=value]  Set an option. When the value is omitted, booleans are
                        set to true, strings and integers are set to None (if
                        permitted), and sequences are emptied. Boolean values
                        can be true, false or toggle.
  -q, --quiet           Quiet.
  -v, --verbose         Increase log verbosity.
  --mode MODE, -m MODE  Mode can be "regular", "transparent", "socks5",
                        "reverse:SPEC", or "upstream:SPEC". For reverse and
                        upstream proxy modes, SPEC is host specification in
                        the form of "http[s]://host[:port]".
  --no-anticache
  --anticache           Strip out request headers that might cause the server
                        to return 304-not-modified.
  --no-showhost
  --showhost            Use the Host header to construct URLs for display.
  --rfile PATH, -r PATH
                        Read flows from file.
  --scripts SCRIPT, -s SCRIPT
                        Execute a script. May be passed multiple times.
  --stickycookie FILTER
                        Set sticky cookie filter. Matched against requests.
  --stickyauth FILTER   Set sticky auth filter. Matched against requests.
  --save-stream-file PATH, -w PATH
                        Stream flows to file as they arrive. Prefix path with
                        + to append.
  --no-anticomp
  --anticomp            Try to convince servers to send us un-compressed data.
  --flow-detail LEVEL   The display detail level for flows in mitmdump: 0
                        (almost quiet) to 3 (very verbose). 0: shortened
                        request URL, response status code, WebSocket and TCP
                        message notifications. 1: full request URL with
                        response status code 2: 1 + HTTP headers 3: 2 + full
                        response content, content of WebSocket and TCP
                        messages.

Proxy Options:
  --listen-host HOST    Address to bind proxy to.
  --listen-port PORT, -p PORT
                        Proxy service port.
  --no-server, -n
  --server              Start a proxy server. Enabled by default.
  --ignore-hosts HOST   Ignore host and forward all traffic without processing
                        it. In transparent mode, it is recommended to use an
                        IP address (range), not the hostname. In regular mode,
                        only SSL traffic is ignored and the hostname should be
                        used. The supplied value is interpreted as a regular
                        expression and matched on the ip or the hostname. May
                        be passed multiple times.
  --allow-hosts HOST    Opposite of --ignore-hosts. May be passed multiple
                        times.
  --tcp-hosts HOST      Generic TCP SSL proxy mode for all hosts that match
                        the pattern. Similar to --ignore, but SSL connections
                        are intercepted. The communication contents are
                        printed to the log in verbose mode. May be passed
                        multiple times.
  --upstream-auth USER:PASS
                        Add HTTP Basic authentication to upstream proxy and
                        reverse proxy requests. Format: username:password.
  --proxyauth SPEC      Require proxy authentication. Format: "username:pass",
                        "any" to accept any user/pass combination, "@path" to
                        use an Apache htpasswd file, or
                        "ldap[s]:url_server_ldap:dn_auth:password:dn_subtree"
                        for LDAP authentication.
  --no-rawtcp
  --rawtcp              Enable/disable experimental raw TCP support. TCP
                        connections starting with non-ascii bytes are treated
                        as if they would match tcp_hosts. The heuristic is
                        very rough, use with caution. Disabled by default.
  --no-http2
  --http2               Enable/disable HTTP/2 support. HTTP/2 support is
                        enabled by default.

SSL:
  --certs SPEC          SSL certificates of the form "[domain=]path". The
                        domain may include a wildcard, and is equal to "*" if
                        not specified. The file at path is a certificate in
                        PEM format. If a private key is included in the PEM,
                        it is used, else the default key in the conf dir is
                        used. The PEM file should contain the full certificate
                        chain, with the leaf certificate as the first entry.
                        May be passed multiple times.
  --no-ssl-insecure
  --ssl-insecure, -k    Do not verify upstream server SSL/TLS certificates.
  --key-size KEY_SIZE   TLS key size for certificates and CA.

Client Replay:
  --client-replay PATH, -C PATH
                        Replay client requests from a saved file. May be
                        passed multiple times.

Server Replay:
  --server-replay PATH, -S PATH
                        Replay server responses from a saved file. May be
                        passed multiple times.
  --no-server-replay-kill-extra
  --server-replay-kill-extra
                        Kill extra requests during replay.
  --no-server-replay-nopop
  --server-replay-nopop
                        Don't remove flows from server replay state after use.
                        This makes it possible to replay same response
                        multiple times.
  --no-server-replay-refresh
  --server-replay-refresh
                        Refresh server replay responses by adjusting date,
                        expires and last-modified headers, as well as
                        adjusting cookie expiration.

Map Remote:
  --map-remote PATTERN, -M PATTERN
                        Map remote resources to another remote URL using a
                        pattern of the form "[/flow-filter]/url-
                        regex/replacement", where the separator can be any
                        character. May be passed multiple times.

Map Local:
  --map-local PATTERN   Map remote resources to a local file using a pattern
                        of the form "[/flow-filter]/url-regex/file-or-
                        directory-path", where the separator can be any
                        character. May be passed multiple times.

Modify Body:
  --modify-body PATTERN, -B PATTERN
                        Replacement pattern of the form "[/flow-
                        filter]/regex/[@]replacement", where the separator can
                        be any character. The @ allows to provide a file path
                        that is used to read the replacement string. May be
                        passed multiple times.

Modify Headers:
  --modify-headers PATTERN, -H PATTERN
                        Header modify pattern of the form "[/flow-
                        filter]/header-name/[@]header-value", where the
                        separator can be any character. The @ allows to
                        provide a file path that is used to read the header
                        value string. An empty header-value removes existing
                        header-name headers. May be passed multiple times.
```
