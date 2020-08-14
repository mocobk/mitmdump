# -*- coding:utf-8 -*-  
# __auth__ = mocobk
# email: mailmzb@qq.com

import setuptools

with open("README.md", "r", encoding='utf-8') as fh:
    long_description = fh.read()

setuptools.setup(
    name="mitmdump",
    version="1.0.3",
    author="mocobk",
    author_email="mailmzb@qq.com",
    description="以编程的方式运行 mitmproxy",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mocobk/mitmdump",
    packages=['mitmdump'],
    install_requires=['mitmproxy'],
    classifiers=[
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    extras_require={
        ':sys_platform == "win32"': [
            "pydivert>=2.0.3,<2.2",
        ],
        ':python_version == "3.6"': [
            "dataclasses>=0.7",
        ]
    }
)
