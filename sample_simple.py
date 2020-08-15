#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : mocobk
# @Email  : mailmzb@qq.com
# @Time   : 2020/8/13 12:29
from mitmproxy import ctx
from mitmproxy.http import HTTPFlow

from mitmdump import DumpMaster, Options


def request(flow: HTTPFlow):
    ctx.log.info(flow.request.path)


if __name__ == '__main__':
    opts = Options(listen_host='0.0.0.0', listen_port=8888, scripts=__file__)
    m = DumpMaster(opts)
    m.run()
