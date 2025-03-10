import os
import time
import hashlib
import xml.etree.ElementTree as ET
from flask import Flask, request, Response, jsonify, abort
import requests
import redis
import logging
import urllib.parse
import json
from WXBizMsgCrypt3 import WXBizMsgCrypt  # 企业微信官方提供的加解密工具
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor

# 初始化 Flask 应用
app = Flask(__name__)
redis_client = redis.Redis(host='localhost', port=6379, db=0)

# 配置日志记录器
logging.basicConfig(filename='access.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# 请求前的处理
@app.before_request
def log_request_info():
    ip = request.remote_addr
    method = request.method
    url = request.url
    headers = request.headers
    body = request.get_data() if request.is_json else request.form.to_dict() if request.form else {}
    logging.info(f"Request: IP={ip}, Method={method}, URL={url}, Headers={headers}, Body={body}")

# 请求后的处理
@app.after_request
def log_response_info(response):
    status = response.status_code
    headers = response.headers
    context = response.data
    logging.info(f"Response: Status={status}, Headers={headers}, Context={context}")
    return response

# 配置信息（建议使用环境变量）
CONFIG = {
    "CORP_ID": os.getenv("WECOM_CORP_ID", "your_corp_id"),
    "AGENT_ID": os.getenv("WECOM_AGENT_ID", "your_agent_id"),
    "SECRET": os.getenv("WECOM_SECRET", "your_secret"),
    "TOKEN": os.getenv("WECOM_TOKEN", "your_token"),
    "AES_KEY": os.getenv("WECOM_AES_KEY", "your_aes_key"),
    "DEEPSEEK_API_KEY": os.getenv("DEEPSEEK_API_KEY", "your_api_key"),
    "DEEPSEEK_API_URL": "https://api.deepseek.com/v1/chat/completions",
    "REDIS_URL": os.getenv("REDIS_URL", "redis://localhost:6379/0"),
}

# 初始化 Redis 连接
redis_client = redis.from_url(CONFIG['REDIS_URL'])

# 初始化企业微信加解密工具
wx_crypt = WXBizMsgCrypt(
    CONFIG['TOKEN'],
    CONFIG['AES_KEY'],
    CONFIG['CORP_ID']
)

def get_wecom_access_token():
    """获取企业微信 Access Token"""
    cache_key = f"wecom_access_token:{CONFIG['AGENT_ID']}"
    token = redis_client.get(cache_key)
    if token:
        return token.decode()

    url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={CONFIG['CORP_ID']}&corpsecret={CONFIG['SECRET']}"
    resp = requests.get(url).json()
    if resp['errcode'] == 0:
        redis_client.setex(cache_key, 7000, resp['access_token'])
        return resp['access_token']
    raise Exception(f"Failed to get access token: {resp}")

async def call_deepseek(query, history=[]):
    """调用 DeepSeek API"""
    headers = {
        "Authorization": f"Bearer {CONFIG['DEEPSEEK_API_KEY']}",
        "Content-Type": "application/json"
    }

    messages = history + [{"role": "user", "content": query}]
    if len(messages) > 0 and messages[0]["role"] != "user":
        messages.insert(0, {"role": "user", "content": "开始对话"})
    for msg in history:
        if msg["role"] == "assistant" and not msg.get("content") and not msg.get("tool_calls"):
            msg["content"] = ""
    data = {
        "messages": messages[-10:],  # 控制上下文长度
        "model": "deepseek-chat",
        "temperature": 0.7,
        "max_tokens": 1500
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                CONFIG['DEEPSEEK_API_URL'],
                headers=headers,
                json=data,
                timeout=120
            ) as response:
                result = await response.json()

                if response.status != 200:
                    app.logger.error(f"DeepSeek API Error: {result}")
                    return None
                
                if response.status == 200:
                    print(result['choices'][0]['message']['content'].strip())
                    return result['choices'][0]['message']['content'].strip()
    except asyncio.TimeoutError:
        return "请求超时，请重试"
    except Exception as e:
        app.logger.error(f"API调用异常: {str(e)}")
        return None

def send_wecom_message(user_id, message_content):
    """发送企业微信消息"""
    access_token = get_wecom_access_token()
    url = f"https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={access_token}"
    payload = {
        "touser": user_id,
        "msgtype": "text",
        "agentid": CONFIG['AGENT_ID'],
        "text": {
            "content": message_content
        },
        "safe": 0
    }
    headers = {'Content-Type': 'application/json'}
    response = requests.post(url, headers=headers, data=json.dumps(payload))
    if response.status_code != 200 or response.json().get('errcode') != 0:
        app.logger.error(f"Failed to send WeChat message: {response.text}")
    else:
        app.logger.info(f"Successfully sent WeChat message to user_id: {user_id}")

@app.route('/wechat', methods=['GET', 'POST'])
def handle_wechat():
    """企业微信消息入口"""
    if request.method == 'GET':
        # 验证回调 URL
        msg_signature = urllib.parse.unquote(request.args.get('msg_signature', ''))
        timestamp = urllib.parse.unquote(request.args.get('timestamp', ''))
        nonce = urllib.parse.unquote(request.args.get('nonce', ''))
        echo_str = urllib.parse.unquote(request.args.get('echostr', ''))

        ret, decrypt_echo_str = wx_crypt.VerifyURL(msg_signature, timestamp, nonce, echo_str)
        if ret != 0:
            abort(403)
        return decrypt_echo_str

    elif request.method == 'POST':
        # 处理消息
        msg_signature = urllib.parse.unquote(request.args.get('msg_signature', ''))
        timestamp = urllib.parse.unquote(request.args.get('timestamp', ''))
        nonce = urllib.parse.unquote(request.args.get('nonce', ''))
        encrypted_msg = urllib.parse.unquote(request.data.decode('utf-8'))

        # 解密消息
        ret, decrypt_msg = wx_crypt.DecryptMsg(encrypted_msg, msg_signature, timestamp, nonce)
        if ret != 0:
            abort(403)

        # 解析 XML 消息
        root = ET.fromstring(decrypt_msg)
        msg_type = root.find('MsgType').text
        user_id = root.find('FromUserName').text
        content = root.find('Content').text if msg_type == 'text' else ''
        msgid = root.find('MsgId').text

        # 处理文本消息
        if msg_type == 'text' and content.strip():
            # 获取上下文
            context_key = f"deepseek_context:{user_id}"
            history = json.loads(redis_client.get(context_key) or '[]')
            if len(history) > 10:
                redis_client.delete(context_key)

            # 立即返回空响应以延迟超时时间
            reply_xml = f"""
            <xml>
                <ToUserName><![CDATA[{user_id}]]></ToUserName>
                <FromUserName><![CDATA[{CONFIG['AGENT_ID']}]]></FromUserName>
                <CreateTime>{int(time.time())}</CreateTime>
                <MsgType><![CDATA[text]]></MsgType>
                <Content><![CDATA[]]></Content>
            </xml>
            """
            ret, encrypt_reply_msg = wx_crypt.EncryptMsg(reply_xml, nonce, timestamp)
            if ret != 0:
                abort(500)
            resp = Response(encrypt_reply_msg, mimetype='application/xml')
            resp.status_code = 200

            # 异步处理 DeepSeek 请求
            executor.submit(process_deepseek_request, content, history, user_id, msgid)

            return resp
        return 'success'
def split_message(message: str, max_bytes: int = 2048) -> list[str]:
    encoded = message.encode('utf-8')
    total = len(encoded)
    chunks = []
    start = 0
    
    while start < total:
        end = start + max_bytes
        # 如果当前分片超出总长度，直接取剩余部分
        if end >= total:
            chunks.append(encoded[start:].decode('utf-8'))
            break
        # 调整分片结束位置以避免截断多字节字符
        while end > start and (encoded[end] & 0xC0) == 0x80:
            end -= 1
        # 处理无法分割的情况（极少数情况，如max_bytes过小）
        if end <= start:
            end = start + max_bytes
            # 强制分割并忽略无效字节（根据需求调整）
            chunk = encoded[start:end]
            # 使用replace错误处理忽略无效字节
            chunks.append(chunk.decode('utf-8', errors='replace'))
            start = end
            continue
        # 添加分片并解码
        chunk = encoded[start:end]
        chunks.append(chunk.decode('utf-8'))
        start = end
    
    return chunks
def process_deepseek_request(content, history, user_id, msgid):
    try:
        app.logger.info(f"Starting process_deepseek_request for user_id: {user_id}, msgid: {msgid}")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        response_text = loop.run_until_complete(call_deepseek(content, history))
        loop.close()

        if response_text is None:
            response_text = "当前服务繁忙，请稍后再试"

        # 更新上下文（保留最近5轮对话）
        new_history = history + [
            {"role": "user", "content": content},
            {"role": "assistant", "content": response_text}
        ][-10:]  # 保留最近5轮对话
        redis_client.setex(f"deepseek_context:{user_id}", 8000, json.dumps(new_history))
        if len(response_text.encode('utf-8')) > 2048:
            response_text_list=split_message(response_text,2048)
            for i in response_text_list:
                time.sleep(1)
                send_wecom_message(user_id, i)
        else:
            send_wecom_message(user_id, response_text)# 主动发送消息给用户
    except Exception as e:
        app.logger.error(f"Error processing DeepSeek request: {str(e)}")

if __name__ == '__main__':
    get_wecom_access_token()
    executor = ThreadPoolExecutor(max_workers=10)  # 创建线程池执行器
    app.run(host='0.0.0.0', port=62222, debug=True)



