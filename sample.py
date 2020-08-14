#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : mocobk
# @Email  : mailmzb@qq.com
# @Time   : 2020/8/13 12:29
from mitmproxy import flowfilter, ctx
from mitmproxy.http import HTTPFlow

from mitmdump import DumpMaster, Options

class AddHeader:
    def __init__(self):
        self.num = 0

    def response(self, flow: HTTPFlow):
        self.num = self.num + 1
        flow.response.headers["count"] = str(self.num)


class FilterFlow:
    def __init__(self):
        self.filter = None

    def load(self, loader):
        self.filter = flowfilter.parse(ctx.options.dumper_filter)

    def request(self, flow: HTTPFlow):
        if flowfilter.match(self.filter, flow):
            print(flow.request.url)

    def response(self, flow: HTTPFlow):
        if flowfilter.match(self.filter, flow):
            print(flow.response.headers)


addons = [
    AddHeader(),
    FilterFlow()
]

if __name__ == '__main__':
    opts = Options(server=True, listen_host='0.0.0.0', listen_port=8888, termlog_verbosity='info',
                   show_clientconnect_log=False, flow_detail=1, dumper_filter='~m POST')
    m = DumpMaster(opts)

    m.addons.add(*addons)
    m.run()
