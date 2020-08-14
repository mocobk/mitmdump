#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : mocobk
# @Email  : mailmzb@qq.com
# @Time   : 2020/8/13 15:49
import asyncio
import os
import signal
import sys
import traceback
import typing

from mitmproxy import exceptions
from mitmproxy import http
from mitmproxy import options
from mitmproxy import proxy
from mitmproxy.net.http import http1
from mitmproxy.tools import dump


class ProxyServer(proxy.server.ProxyServer):
    def handle_client_connection(self, conn, client_address):
        h = ConnectionHandler(
            conn,
            client_address,
            self.config,
            self.channel
        )
        h.handle()


class ConnectionHandler(proxy.server.ConnectionHandler):
    def handle(self):
        show_clientconnect_log = hasattr(self.config.options,
                                         'show_clientconnect_log') and self.config.options.show_clientconnect_log
        if show_clientconnect_log:
            self.log("clientconnect", "info")

        root_layer = None
        try:
            root_layer = self._create_root_layer()
            root_layer = self.channel.ask("clientconnect", root_layer)
            root_layer()
        except exceptions.Kill:
            self.log("Connection killed", "info")
        except exceptions.ProtocolException as e:
            if isinstance(e, exceptions.ClientHandshakeException):
                self.log(
                    "Client Handshake failed. "
                    "The client may not trust the proxy's certificate for {}.".format(e.server),
                    "warn"
                )
                self.log(repr(e), "debug")
            elif isinstance(e, exceptions.InvalidServerCertificate):
                self.log(str(e), "warn")
                self.log("Invalid certificate, closing connection. Pass --ssl-insecure to disable validation.", "warn")
            else:
                self.log(str(e), "warn")

                self.log(repr(e), "debug")
            # If an error propagates to the topmost level,
            # we send an HTTP error response, which is both
            # understandable by HTTP clients and humans.
            try:
                error_response = http.make_error_response(502, repr(e))
                self.client_conn.send(http1.assemble_response(error_response))
            except exceptions.TcpException:
                pass
        except Exception:
            self.log(traceback.format_exc(), "error")
            print(traceback.format_exc(), file=sys.stderr)
            print("mitmproxy has crashed!", file=sys.stderr)
            print("Please lodge a bug report at: https://github.com/mitmproxy/mitmproxy", file=sys.stderr)

        if show_clientconnect_log:
            self.log("clientdisconnect", "info")
        if root_layer is not None:
            self.channel.tell("clientdisconnect", root_layer)
        self.client_conn.finish()


class Options(options.Options):
    def __init__(self,
                 listen_host: str = '0.0.0.0',
                 listen_port: int = 8080,
                 dumper_filter: str = None,
                 flow_detail: int = 0,
                 termlog_verbosity: str = 'info',
                 show_clientconnect_log: bool = False,
                 scripts: typing.Sequence[str] = None,
                 mode: str = 'regular',
                 ignore_hosts: typing.Sequence[str] = None,
                 allow_hosts: typing.Sequence[str] = None,
                 save_stream_file: str = None,
                 certs: typing.Sequence[str] = None,
                 **kwargs):
        super().__init__()
        self.add_option(
            "show_clientconnect_log", bool, False,
            "Whether to display clientconnect or clientdisconnect logs."
        )
        scripts = scripts or []
        ignore_hosts = ignore_hosts or []
        allow_hosts = allow_hosts or []
        certs = certs or []
        self._options['kwargs'] = {**dict(listen_host=listen_host,
                                          listen_port=listen_port,
                                          dumper_filter=dumper_filter,
                                          flow_detail=flow_detail,
                                          termlog_verbosity=termlog_verbosity,
                                          show_clientconnect_log=show_clientconnect_log,
                                          scripts=scripts,
                                          mode=mode,
                                          ignore_hosts=ignore_hosts,
                                          allow_hosts=allow_hosts,
                                          save_stream_file=save_stream_file,
                                          certs=certs), **kwargs}


class DumpMaster(dump.DumpMaster):
    def __init__(
            self,
            options: Options = Options(),
            with_termlog=True,
            with_dumper=True,
    ) -> None:
        super().__init__(options, with_termlog, with_dumper)
        # delay update options, avoid raise KeyError: 'Unknown options'
        self.options.update(**self.options._options['kwargs'])
        self.server = ProxyServer(proxy.config.ProxyConfig(self.options))

    def run(self, func=None):
        try:
            loop = asyncio.get_event_loop()
            try:
                loop.add_signal_handler(signal.SIGINT, getattr(self, "prompt_for_exit", self.shutdown))
                loop.add_signal_handler(signal.SIGTERM, self.shutdown)
            except NotImplementedError:
                # Not supported on Windows
                pass

            # Make sure that we catch KeyboardInterrupts on Windows.
            # https://stackoverflow.com/a/36925722/934719
            if os.name == "nt":
                async def wakeup():
                    while True:
                        await asyncio.sleep(0.2)

                asyncio.ensure_future(wakeup())

            super().run()
        except (KeyboardInterrupt, RuntimeError):
            pass
