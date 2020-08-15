#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : mocobk
import logging
import typing

from mitmproxy import log, addonmanager, flow
from mitmproxy.http import HTTPFlow

from mitmdump import DumpMaster, Options

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s %(message)s')


class AddHeader:
    def __init__(self):
        self.num = 0

    def load(self, loader: addonmanager.Loader):
        """
            Called when an addon is first loaded. This event receives a Loader
            object, which contains methods for adding options and commands. This
            method is where the addon configures itself.
        """
        logging.info('load')

    def running(self):
        """
            Called when the proxy is completely up and running. At this point,
            you can expect the proxy to be bound to a port, and all addons to be
            loaded.
        """
        logging.info('running')

    def configure(self, updated: typing.Set[str]):
        """
            Called when configuration changes. The updated argument is a
            set-like object containing the keys of all changed options. This
            event is called during startup with all options in the updated set.

            Just called with scripts params.
            updated: set({'termlog_verbosity', 'upstream_bind_address',...})

        """
        logging.info('configure')

    def update(self, flows: typing.Sequence[flow.Flow]):
        """
            Update is called when one or more flow objects have been modified,
            usually from a different addon.
        """
        logging.info('update')

    def done(self):
        """
            Called when the addon shuts down, either by being removed from
            the mitmproxy instance, or when mitmproxy itself shuts down. On
            shutdown, this event is called after the event loop is
            terminated, guaranteeing that it will be the final event an addon
            sees. Note that log handlers are shut down at this point, so
            calls to log functions will produce no output.
        """
        logging.info('done')

    def log(self, entry: log.LogEntry):
        """
            Called whenever a new log entry is created through the mitmproxy
            context. Be careful not to log from this event, which will cause an
            infinite loop!
        """

    def request(self, flow: HTTPFlow):
        pass


addons = [
    AddHeader(),
]

if __name__ == '__main__':
    opts = Options(listen_host='0.0.0.0', listen_port=8888, scripts=__file__, dumper_filter='~m POST',
                   flow_detail=1, termlog_verbosity='info', show_clientconnect_log=False)
    m = DumpMaster(opts)
    m.run()
