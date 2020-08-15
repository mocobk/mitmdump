#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : mocobk
# @Email  : mailmzb@qq.com
# @Time   : 2020/8/13 12:29
from mitmproxy import flowfilter, ctx, addonmanager
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

    def load(self, loader: addonmanager.Loader):
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
    opts = Options(listen_host='0.0.0.0', listen_port=8888, scripts=None, dumper_filter='~m POST',
                   flow_detail=1, termlog_verbosity='info', show_clientconnect_log=False)
    m = DumpMaster(opts)

    # It's not necessary if scripts parameter is not None
    # 如果你的 scripts 参数不为 None，则下方加载插件的语句不是必须的
    m.addons.add(*addons)

    m.run()
