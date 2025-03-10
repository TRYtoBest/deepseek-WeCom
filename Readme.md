0、需要在企业微信配置一个应用同时拥有一个该企业的域名。然后通过企业微信的回调测试，这里默认的是62222端口回调域名为http://xxx.xx.com:62222/wechat

1、切换到 weworkapi_python\callback 目录

2、pip install Flask==2.0.3 requests==2.26.0 redis==4.3.4 aiohttp==3.8.1 或者 pip install Flask requests redis aiohttp

3、在 conf.sh里配置参数（deepseekAPI，企业微信及应用的一些必要参数），复制到命令行执行（只需要执行export开头的命令）。

4、在callback目录里，命令行执行python3 chatapp.py 即可.（ubuntu）
