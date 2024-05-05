import asyncio, hashlib, json, sys, time, uuid, copy
from curl_cffi.requests import AsyncSession
from eth_account.messages import encode_defunct
from web3 import AsyncWeb3
from loguru import logger

logger.remove()
logger.add(sys.stdout, colorize=True, format="<g>{time:HH:mm:ss:SSS}</g> | <level>{message}</level>")


class Twitter:
    def __init__(self, auth_token):
        self.auth_token = auth_token
        bearer_token = "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
        defaulf_headers = {
            "authority": "twitter.com",
            "origin": "https://twitter.com",
            "x-twitter-active-user": "yes",
            "x-twitter-client-language": "en",
            "authorization": bearer_token,
        }
        defaulf_cookies = {"auth_token": auth_token}
        self.Twitter = AsyncSession(headers=defaulf_headers, cookies=defaulf_cookies, timeout=120, impersonate="chrome120")
        self.auth_code = None

    async def get_auth_code(self):
        try:
            params = {
                'code_challenge': 'challenge',
                'code_challenge_method': 'plain',
                'client_id': 'c1h0S1pfb010TEVBUnh2N3U3MU86MTpjaQ',
                'redirect_uri': 'https://pioneer.particle.network/signup',
                'response_type': 'code',
                'scope': 'tweet.read users.read',
                'state': f'twitter-{uuid.uuid4()}'
            }
            response = await self.Twitter.get('https://twitter.com/i/api/2/oauth2/authorize', params=params)
            if "code" in response.json() and response.json()["code"] == 353:
                self.Twitter.headers.update({"x-csrf-token": response.cookies["ct0"]})
                return await self.get_auth_code()
            elif response.status_code == 429:
                await asyncio.sleep(5)
                return self.get_auth_code()
            elif 'auth_code' in response.json():
                self.auth_code = response.json()['auth_code']
                return True
            logger.error(f'{self.auth_token} 获取auth_code失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def twitter_authorize(self):
        try:
            if not await self.get_auth_code():
                return False
            data = {
                'approval': 'true',
                'code': self.auth_code,
            }
            response = await self.Twitter.post('https://twitter.com/i/api/2/oauth2/authorize', data=data)
            if 'redirect_uri' in response.text:
                return True
            elif response.status_code == 429:
                await asyncio.sleep(5)
                return self.twitter_authorize()
            logger.error(f'{self.auth_token}  推特授权失败')
            return False
        except Exception as e:
            logger.error(f'{self.auth_token}  推特授权异常：{e}')
            return False


class Discord:
    def __init__(self, dc_token):
        self.dc_token = dc_token
        defaulf_headers = {'Authorization': dc_token}
        self.Discord = AsyncSession(headers=defaulf_headers, timeout=120, impersonate="chrome120")
        self.auth_code = None

    async def authorize(self):
        try:
            params = {
                'client_id': '1229361725870964818',
                'response_type': 'code',
                'redirect_uri': 'https://pioneer.particle.network/signup',
                'scope': 'identify email',
                'state': f'discord-{uuid.uuid4()}'
            }
            json_data = {
                "guild_id": "1228788879209922691",
                "permissions": "0",
                "authorize": True,
                "integration_type": 0
            }
            res = await self.Discord.post('https://discord.com/api/v9/oauth2/authorize', params=params, json=json_data)
            if res.status_code == 200 and 'location' in res.text:
                location = res.json()['location']
                self.auth_code = location.split('code=')[1].split('&')[0]
                return True
            logger.error(f'[{self.dc_token}] 获取Discord授权失败：{res.text}')
            return False
        except Exception as e:
            logger.error(f'[{self.dc_token}] 绑定discord异常：{e}')
            return False


class CF:
    def __init__(self, clientKey):
        self.http = AsyncSession(timeout=120, impersonate="chrome120")
        self.clientKey = clientKey
        self.taskId = None

    async def createTaskcapsolver(self):
        json_data = {
            "clientKey": self.clientKey,
            "appId": "69AE5D43-F131-433D-92C8-0947B2CF150A",
            "task": {
                "type": "AntiTurnstileTaskProxyLess",
                "websiteURL": 'https://pioneer.particle.network/zh-CN/point',
                "websiteKey": '0x4AAAAAAAPesjutGoykVbu0'
            }
        }
        for _ in range(3):
            try:
                response = await self.http.post('https://api.capsolver.com/createTask', json=json_data)
                if response.json()['errorId'] == 0:
                    self.taskId = response.json()['taskId']

                    return True
            except:
                pass
        return False

    async def capsolver(self):
        if not await self.createTaskcapsolver():
            return None
        json_data = {
            "clientKey": self.clientKey,
            "taskId": self.taskId
        }
        for _ in range(30):
            try:
                response = await self.http.post('https://api.capsolver.com/getTaskResult', json=json_data)
                if response.json()['errorId'] == 0 and response.json()['status'] == 'ready':
                    return response.json()['solution']['token']
                elif response.json()['errorId'] == 1:
                    return None
            except:
                pass
            await asyncio.sleep(3)
        return None


class Account:
    def __init__(self, private_key: str, auth_token: str, dc_token: str, cap_clientKey: str):
        self.http = AsyncSession(timeout=120, impersonate="chrome120")
        self.http.headers.update({
            "Authorization": "Basic OUMzUnRxQmNCcUJuQk5vYjo3RGJubng3QlBxOENBOFBI",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
        })
        self.twitter = Twitter(auth_token)
        self.discord = Discord(dc_token)
        self.CF = CF(cap_clientKey)
        self.w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider('https://bsc-dataseed.binance.org/'))
        self.account = self.w3.eth.account.from_key(private_key)
        self.device_id = str(uuid.uuid4())
        self.macKey = "5706dd1db5aabc45c649ecc01fdac97100de8e8655715d810d0fb2080e6cea24"

    @staticmethod
    def sha256(data: dict):
        hash_object = hashlib.sha256()
        hash_object.update(json.dumps(data).replace(' ', '').encode())
        hex_dig = hash_object.hexdigest()
        return hex_dig

    async def post(self, url: str, json_data: dict):
        try:
            random_str = str(uuid.uuid4())
            timestamp = int(time.time())
            params = {
                "device_id": self.device_id,
                "project_app_uuid": "79df412e-7e9d-4a19-8484-a2c8f3d65a2e",
                "project_client_key": "cOqbmrQ1YfOuBMo0KKDtd15bG1ENRoxuUa7nNO76",
                "project_uuid": "91bf10e7-5806-460d-95af-bef2a3122e12",
                "random_str": random_str,
                "sdk_version": "web_1.0.0",
                "timestamp": timestamp
            }
            mac_info = copy.deepcopy(json_data)
            mac_info.update(params)
            mac_info["mac_key"] = self.macKey
            mac = self.sha256(dict(sorted(mac_info.items())))
            params["mac"] = mac
            res = await self.http.post(url, params=params, json=json_data)
            return res
        except Exception as e:
            logger.error(f"提交数据失败，{e}")
            return False

    async def login(self):
        try:
            sig_msg = f"Welcome to Particle Pioneer!\n\nWallet address:\n{self.account.address}\n\nNonce:\n{self.device_id}"
            signature = self.account.sign_message(encode_defunct(text=sig_msg)).signature.hex()
            json_data = {
                "loginMethod": "evm_wallet",
                "loginSource": "okx",
                "loginInfo": {"address": self.account.address.lower(), "signature": signature}
            }
            res = await self.post('https://pioneer-api.particle.network/users', json_data)
            if 'twitter' in res.text:
                logger.info(f"[{self.account.address}]登录成功")
                token = res.json()['token']
                self.macKey = res.json()['macKey']
                self.http.headers.update({"Authorization": f"Bearer {token}"})
                referrerAddress = res.json()['referrerAddress']
                twitter = res.json()['twitter']
                discord = res.json()['discord']
                aaAddress = res.json()['aaAddress']
                if referrerAddress is None:
                    logger.info(f"[{self.account.address}]没有推荐人")
                    await self.bindReferrerAddress('JFGAZG')
                if twitter is None:
                    logger.info(f"[{self.account.address}]没有绑定Twitter")
                    await self.bindTwitter()
                if discord is None:
                    logger.info(f"[{self.account.address}]没有绑定Discord")
                    await self.bindDiscord()
                return True
            return True
        except Exception as e:
            logger.error(f"登录失败，{e}")
            return False

    async def bindReferrerAddress(self, code: str):
        try:
            json_data = {"code": code}
            res = await self.post('https://pioneer-api.particle.network/users/invitation_code', json_data)
            if 'referrerAddress' in res.text:
                logger.info(f"[{self.account.address}]绑定推荐人成功")
                return True
            return False
        except Exception as e:
            logger.error(f"绑定推荐人失败，{e}")
            return False

    async def bindTwitter(self):
        try:
            if not await self.twitter.twitter_authorize():
                return False
            print(self.twitter.auth_code)
            cf_token = await self.CF.capsolver()
            print(cf_token)
            if cf_token is None:
                return False
            json_data = {
                "code": self.twitter.auth_code,
                "provider": "twitter",
                "cfTurnstileResponse": cf_token,
            }
            res = await self.post('https://pioneer-api.particle.network/users/bind', json_data)
            if 'twitter' in res.text:
                logger.info(f"[{self.account.address}]绑定Twitter成功")
                return True
            return False
        except Exception as e:
            logger.error(f"绑定Twitter失败，{e}")
            return False

    async def bindDiscord(self):
        try:
            if not await self.discord.authorize():
                return False
            cf_token = await self.CF.capsolver()
            if cf_token is None:
                return False
            json_data = {
                "code": self.discord.auth_code,
                "provider": "discord",
                "cfTurnstileResponse": cf_token,
            }
            res = await self.post('https://pioneer-api.particle.network/users/bind', json_data)
            if 'discord' in res.text:
                logger.info(f"[{self.account.address}]绑定Discord成功")
                return True
            return False
        except Exception as e:
            logger.error(f"绑定Discord失败，{e}")
            return False


async def main():
    await Account('private_key', 'twitter_auth_token', 'dc_token', 'capsolver_clientKey').login()


if __name__ == '__main__':
    asyncio.run(main())
