import requests
import json
import random
import hashlib
import base64
import time
import re
import os
from requests.cookies import RequestsCookieJar
import string
from urllib.parse import urlparse, parse_qs
import unidecode
from itertools import cycle
import urllib3
import pickle
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class OCB:
    def __init__(self, username, password, account_number,proxy_list=None):
        self.proxy_list = proxy_list
        if self.proxy_list:
            self.proxy_info = random.choice(self.proxy_list)
            proxy_host, proxy_port, username_proxy, password_proxy = self.proxy_info.split(':')
            self.proxies = {
                'http': f'http://{username_proxy}:{password_proxy}@{proxy_host}:{proxy_port}',
                'https': f'http://{username_proxy}:{password_proxy}@{proxy_host}:{proxy_port}'
            }
        else:
            self.proxies = None
        self.file = f"data/ocb/users/{account_number}.json"
        self.cookies_file = f"data/ocb/cookies/{account_number}.pkl"
        self.session = requests.Session()
        self.state = self.get_imei()
        self.nonce = self.state
        self.code_verifier = ''.join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=96))
        self.code_challenge = self.get_code_challenge(self.code_verifier)
        self.cookies = RequestsCookieJar()
        self.username = username
        self.password = password
        self.account_number = account_number
        self.auth_token = None
        self.refresh_token = None
        self.identification_id = None
        self.name_account = None
        self.is_login = False
        self.balance = None
        self.id = None
        self.fullname = None
        self.serviceAgreementId = None
        self.pending_transfer = []
        if not os.path.exists(self.file):
            self.username = username
            self.password = password
            self.account_number = account_number
            self.fullname = None
            self.auth_token = None
            self.refresh_token = None
            self.is_login = False
            self.pending_transfer = []
            self.user_agent = self.get_user_agent()
            self.save_data()
        else:
            self.parse_data()
            self.username = username
            self.password = password
            self.account_number = account_number
            self.save_data()
            

        self.init_data()
    def extract_error_message(self,html_content):
        pattern = r'<span\s+id="template-error-message"\s+class="bb-input-validation-message d-flex justify-content-center hidden"\s+aria-live="polite"\s*>(.*)</span>'
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    def init_data(self):
        self.state = self.get_imei()
        self.nonce = self.get_imei()
        self.code_verifier = ''.join(random.choices(string.ascii_letters + string.digits, k=96))
        self.code_challenge = self.get_code_challenge(self.code_verifier)
        loginOCB(self)
    def save_data(self):
        data = {
            'username': self.username,
            'password': self.password,
            'account_number': self.account_number,
            'identification_id': self.identification_id,
            'balance': self.balance,
            'id': self.id,
            'fullname': self.fullname,
            'is_login': self.is_login,
            'auth_token': self.auth_token,
            'refresh_token': self.refresh_token,
            'pending_transfer': self.pending_transfer,
            'user_agent': self.user_agent
        }
        with open(f"data/ocb/users/{self.account_number}.json", 'w') as file:
            json.dump(data, file)
    def set_token(self, data):
        self.auth_token = data['access_token']
        self.refresh_token = data['refresh_token']
        self.time_set_token = time.time()
    def parse_data(self):
        with open(f"data/ocb/users/{self.account_number}.json", 'r') as file:
            data = json.load(file)
            self.username = data['username']
            self.password = data['password']
            self.account_number = data['account_number']
            self.identification_id = data['identification_id']
            self.balance = data['balance']
            self.id = data['id']
            self.fullname = data['fullname']
            self.is_login = data['is_login']
            self.auth_token = data['auth_token']
            self.refresh_token = data['refresh_token']
            self.pending_transfer = data['pending_transfer']
            self.user_agent = data['user_agent']
    # def save_cookies(self, cookie_jar):
    #     # Load existing cookies from the file if it exists
    #     if os.path.exists(self.cookies_file):
    #         with open(self.cookies_file, 'r') as f:
    #             try:
    #                 existing_cookies = json.load(f)
    #             except json.JSONDecodeError:
    #                 existing_cookies = {}
    #     else:
    #         existing_cookies = {}

    #     # Update the existing cookies with the new cookies
    #     updated_cookies = {**existing_cookies, **cookie_jar.get_dict()}

    #     # Save the updated cookies back to the file
    #     with open(self.cookies_file, 'w') as f:
    #         json.dump(updated_cookies, f)
    # def load_cookies(self):
    #     try:
    #         with open(self.cookies_file, 'r') as f:
    #             cookies = json.load(f)
    #             self.session.cookies.update(cookies)
    #             # self.session.cookies.clear()
    #             return
    #     except (FileNotFoundError, json.decoder.JSONDecodeError):
    #         return requests.cookies.RequestsCookieJar()
    # def save_cookies(self,cookie_jar):
    #     cookies = []
    #     for cookie in self.session.cookies:
    #         cookies.append({
    #             'Name': cookie.name,
    #             'Value': cookie.value,
    #             'Domain': cookie.domain,
    #             'Path': cookie.path,
    #             'Expires': cookie.expires,
    #             'Secure': cookie.secure,
    #             'HttpOnly': cookie.has_nonstandard_attr('HttpOnly')
    #         })
    #     with open(self.cookies_file, 'w') as file:
    #         json.dump(cookies, file, indent=4)

    # def load_cookies(self):
    #     try:
    #         with open(self.cookies_file, 'r') as file:
    #             cookies = json.load(file)
    #             for cookie in cookies:
    #                 self.session.cookies.set(cookie['Name'], cookie['Value'])
    #     except (FileNotFoundError, json.decoder.JSONDecodeError):
    #         return requests.cookies.RequestsCookieJar()
    # def change_proxy(self):
    #         print('change_proxy')
    #         if not self.proxy_cycle:
    #             print("No proxies available. Setting self.proxies to None.")
    #             self.proxies = None
    #             return
    #         self.proxy_info = next(self.proxy_cycle)  # Lấy proxy kế tiếp từ vòng lặp
    #         proxy_host, proxy_port, username_proxy, password_proxy = self.proxy_info.split(':')
    #         self.proxies = {
    #             'http': f'http://{username_proxy}:{password_proxy}@{proxy_host}:{proxy_port}',
    #             'https': f'http://{username_proxy}:{password_proxy}@{proxy_host}:{proxy_port}'
    #         }
    #         print(f"New proxy: {self.proxies}")
    def save_cookies(self,s):
        """Save the current session to a file."""
        with open(self.cookies_file, 'wb') as file:
            pickle.dump(self.session.cookies, file)
    def load_cookies(self):
        """Load a session from a file."""
        try:
            with open(self.cookies_file, 'rb') as file:
                loaded_cookies = pickle.load(file)
            self.session.cookies.update(loaded_cookies)
        except FileNotFoundError:
            print(f"File not found.")
        except Exception as e:
            print(f"An error occurred: {e}")
    def curl_post(self, url,headers,data,proxies=None,allow_redirects=False):
        try:
            
            response = self.session.post(url, headers=headers, data=data,proxies=proxies,verify=False,timeout=7,allow_redirects=allow_redirects)
            return response
        except Exception as e:
            # print('reason change proxy',e)
            # self.change_proxy()
            return None
    def curl_get(self, url,headers,proxies=None):
        try:
            response = self.session.get(url, headers=headers,proxies=proxies,verify=False,timeout=7)
            return response
        except Exception as e:
            # print('reason change proxy',e)
            # self.change_proxy()
            return None
    def get_login_url(self):
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'max-age=0',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-site',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': self.user_agent,
            'sec-ch-ua': '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            }
        params = {
            "client_id": "bb-web-client",
            "redirect_uri": "https://ocbomni.ocb.com.vn/en-US/select-context",
            "state": self.state,
            "response_type": "code",
            "scope": "openid",
            "nonce": self.nonce,
            "ui_locales": "vi",
            "code_challenge": self.code_challenge,
            "code_challenge_method": "S256"
        }

        base_url = "https://identity-omni.ocb.com.vn/auth/realms/backbase/protocol/openid-connect/auth"
        query_string = "&".join([f"{key}={value}" for key, value in params.items()])
        url = f"{base_url}?{query_string}"

        self.load_cookies()
        res = self.curl_get(url, headers=headers,proxies=self.proxies)
        # print(url,res)
        # print(res.url)
        if res:
            session_state,code = self.get_session_and_code(res.url)
        else:
            return self.get_login_url()
        session_state,code = self.get_session_and_code(res.url)
        if session_state and code:
            return session_state,code
        # with open("login_url.html", "w", encoding="utf-8") as file:
        #     file.write(res.text)
        self.save_cookies(self.session.cookies)
        pattern = r'action="(.*)" method'
        matches = re.search(pattern, res.text)
        url = matches.group(1).replace("amp;", "&").replace("&&", "&")
        return url,False

    def send_request_login(self,request_url):
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'max-age=0',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-site',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': self.user_agent,
            'sec-ch-ua': '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            }
        data = {
            'otpChoice': 'PUSH_DEVICE',
        }
        self.load_cookies()
        res = self.curl_post(request_url,headers=headers, data=data,proxies=self.proxies)
        # with open("request_login.html", "w", encoding="utf-8") as file:
        #     file.write(res.text)
        self.save_cookies(self.session.cookies)
        result = res.text
        pattern = r'action="(.*)" method'
        matches = re.search(pattern, res.text)
        url = matches.group(1).replace("amp;", "&").replace("&&", "&")
        return result,url
        
    def do_login(self):
        login_url,session_still = self.get_login_url()
        if session_still:
            session_state,code = login_url,session_still
        else:
            headers = {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Language': 'en-US,en;q=0.9',
                'Cache-Control': 'max-age=0',
                'Connection': 'keep-alive',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-site',
                'Sec-Fetch-User': '?1',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': self.user_agent,
                'sec-ch-ua': '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                }
            data = {
                'username': self.username,
                'password': self.password,
                'locale': 'vi',
                'rememberMe': 'on'
            }
            self.load_cookies()
            res = self.curl_post(login_url,headers=headers, data=data,proxies=self.proxies)
            self.save_cookies(self.session.cookies)
            result = res.text
            # print('url_after_login',res.url)
            session_state,code = self.get_session_and_code(res.url)
        if session_state and code:
            return {
                        'success': True,
                        'code': 200,
                        'message':'Login successful',
                        'session_state': session_state,
                        'code': code
                   }
        error_message = self.extract_error_message(result)
        pattern = r'action="(.*)"'
        matches = re.search(pattern, res.text)
        if matches:
            url = matches.group(1).replace("amp;", "&").replace("&&", "&")
        
        if error_message == 'OMNI_03_MS01':
            error_code = 444
            error_message_details = 'Tên đăng nhập hoặc mật khẩu không đúng. Tài khoản của bạn sẽ bị khóa nếu nhập sai 5 lần.'
        elif error_message == 'MG_OMNI_03_MS01':
            error_code = 444
            error_message_details = 'Tài khoản của bạn sẽ bị khóa nếu nhập sai 5 lần. Vui lòng lấy lại thông tin đăng nhập.'
        elif error_message == 'invalid_username_message':
            error_code = 444
            error_message_details = 'Tên đăng nhập hoặc mật khẩu không đúng. Tài khoản của bạn sẽ bị khóa nếu nhập sai 5 lần.'
        elif error_message == 'OMNI_03_MS02':
            error_code = 444
            error_message_details = 'Tài khoản của bạn chưa thể sử dụng phiên bản OCB OMNI 4.0 này. Bạn vui lòng đăng nhập OCB OMNI trên nền tảng đang đáp ứng.'
        elif error_message == 'OMNI_03_MS03':
            error_code = 449
            error_message_details = 'Tài khoản OCB OMNI đã bị khóa do nhập sai thông tin đăng nhập liên tục 5 lần. Bạn vui lòng đến Chi nhánh OCB gần nhất để được hỗ trợ.'
        elif error_message == 'OMNI_03_MS04':
            error_code = 449
            error_message_details = 'Tài khoản OCB OMNI đã bị khóa theo yêu cầu, bạn vui lòng liên hệ Chi nhánh OCB gần nhất hoặc hotline 18006678 để được hỗ trợ.'
        elif error_message == 'OMNI_03_MS05':
            error_code = 449
            error_message_details = 'Tài khoản OCB OMNI đã bị khóa, bạn vui lòng liên hệ Chi nhánh OCB gần nhất hoặc hotline 18006678 để được hỗ trợ.'
        elif error_message == 'OMNI_03_MS06':
            error_code = 449
            error_message_details = 'Tài khoản OCB OMNI đã bị khóa, bạn vui lòng liên hệ Chi nhánh OCB gần nhất để xác minh và hỗ trợ.'
        elif error_message == 'OMNI_03_MS16':
            error_code = 449
            error_message_details = 'Bạn không thể đăng nhập do đã hủy dịch vụ, vui lòng đăng ký lại để có thể tiếp tục sử dụng OCB OMNI.'
        elif error_message == 'last_attempt_message':
            error_code = 444
            error_message_details = 'Tài khoản của bạn sẽ bị khóa nếu nhập sai 1 lần nữa. Vui lòng lấy lại thông tin đăng nhập.'
        elif error_message == 'account_temporarily_disabled_message':
            error_code = 449
            error_message_details = 'Tài khoản OCB OMNI của bạn hiện đang tạm khóa hoặc đóng dịch vụ. Bạn vui lòng liên hệ Chi nhánh OCB gần nhất để được hỗ trợ.'
        elif error_message == 'account_disabled_message':
            error_code = 448
            error_message_details = 'Tài khoản OCB OMNI đã bị khóa, bạn vui lòng liên hệ Chi nhánh OCB gần nhất hoặc Hotline 18006678 để được hỗ trợ.'
        elif error_message == 'login_session_timeout_message':
            error_code = 401
            error_message_details = 'Phiên đăng nhập đã hết hiệu lực. Bạn vui lòng đăng nhập lại để tiếp tục.'

        if error_message:
            return {
                'success': False,
                'code': error_code,
                'message':error_message_details,
                'ocb_error_code': error_message
            }
        elif 'Xác thực đăng nhập' in result:
            request_login_result,request_url = self.send_request_login(url)
            if 'Chúng tôi đã gửi yêu cầu xác thực tới thiết bị đăng ký của bạn, vui lòng kiểm tra và xác thực trong 2 phút.' in request_login_result:
                   return {
                        'success': True,
                        'code': 201,
                        'message':'Chúng tôi đã gửi yêu cầu xác thực tới thiết bị đăng ký của bạn, vui lòng kiểm tra và xác thực trong 2 phút.',
                        'waiting': True,
                        'url': request_url
                   }
            else:
                    return {
                        'success': False,
                        'code': 500,
                        'message':'Đã xảy ra lỗi',
                        'waiting': False
                   }
        
            
            
            
            


    def check_session(self, url):
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'max-age=0',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-site',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': self.user_agent,
            'sec-ch-ua': '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            }

        data = {
            'oob-authn-action': 'confirmation-poll'
        }
        self.load_cookies()
        res = self.curl_post(url, headers=headers,data=data,proxies=self.proxies)
        self.save_cookies(self.session.cookies)
        result = res.text

        return result
    def continue_check_session(self, url):
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'max-age=0',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-site',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': self.user_agent,
            'sec-ch-ua': '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            }
        data = {
            'oob-authn-action': 'confirmation-continue'
        }
        self.load_cookies()
        response = self.curl_post(url, headers=headers,data=data,allow_redirects=False,proxies=self.proxies)
        self.save_cookies(self.session.cookies)
        if response.status_code == 302:
            new_url = response.headers.get('Location')
            return new_url
        else:
            return None
    def get_token(self,code, url):
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'max-age=0',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-site',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': self.user_agent,
            'sec-ch-ua': '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            }

        data = {
            'code': code,
            'grant_type': 'authorization_code',
            'client_id': 'bb-web-client',
            'redirect_uri': url if url else 'https://ocbomni.ocb.com.vn/login',
            'code_verifier': self.code_verifier,
            'ui_locales': 'vi'
        }

        url = 'https://identity-omni.ocb.com.vn/auth/realms/backbase/protocol/openid-connect/token'
        self.load_cookies()
        response = self.curl_post(url, headers=headers, data=data,proxies=self.proxies)
        self.save_cookies(self.session.cookies)
        result = response.json()

        if 'access_token' in result:
            self.set_token(result)
            self.save_data()
        return result
    # Add other methods from the PHP class as needed
    def logout(self):
        headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-site',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
        'sec-ch-ua': '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
        }

        params = {
            "id_token_hint": self.auth_token,
            "post_logout_redirect_uri": "https://ocbomni.ocb.com.vn/en-US/select-context"
        }

        base_url = "https://identity-omni.ocb.com.vn/auth/realms/backbase/protocol/openid-connect/logout"
        query_string = "&".join([f"{key}={value}" for key, value in params.items()])
        url = f"{base_url}?{query_string}"
        
        self.load_cookies()
        # print(url)
        res = self.curl_get(url, headers=headers,proxies=self.proxies)
        self.save_cookies(self.session.cookies)
        # print(res.url)
        # with open("logout.html", "w", encoding="utf-8") as file:
        #     file.write(res.text)

        return res.text
    
    def do_refresh_token(self):
        headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'vi',
        'Connection': 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Lang': 'vi',
        'Origin': 'https://ocbomni.ocb.com.vn',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-site',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
        'sec-ch-ua': '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'Authorization': f'Bearer {self.auth_token}'
        }

        data = {
            'grant_type': 'refresh_token',
            'client_id': 'bb-web-client',
            'refresh_token': self.refresh_token,
            'scope': 'openid',
            'ui_locales': 'vi'
        }
        self.load_cookies()
        response = self.curl_post('https://identity-omni.ocb.com.vn/auth/realms/backbase/protocol/openid-connect/token', data=data, headers=headers,proxies=self.proxies)
        self.save_cookies(self.session.cookies)
        result = response.json()
        if 'access_token' in result:
            self.set_token(result)
            self.save_data()
        # else:
        #     self.logout()
        return result
    def service_agreements(self):
        headers = {
        'Accept': 'application/json',
        'Accept-Language': 'vi',
        'Authorization': f'Bearer {self.auth_token}',
        'Connection': 'keep-alive',
        'Lang': 'vi',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
        'sec-ch-ua': '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
        }

        self.load_cookies()
        
        url = 'https://ocbomni.ocb.com.vn/api/access-control/client-api/v3/accessgroups/user-context/service-agreements?from=0&size=7'
        response = self.curl_get(url, headers=headers,proxies=self.proxies)
        self.save_cookies(self.session.cookies)
        # print(response.status_code)
        # print('service_agreements',response.text)
        if response.status_code == 200:
            result = response.json()
            self.serviceAgreementId = result[0]['id']
            return result
        else:
            return None
    def user_context(self):
        xsrf_token = ""
        # if self.cookies_file and os.path.exists(self.cookies_file):
        #     with open(self.cookies_file, 'r') as file:
        #         cookies = json.load(file)
        #         xsrf_token = next((cookie['Value'] for cookie in cookies if cookie['Name'] == 'XSRF-TOKEN'), "")
        # print('xsrf_token',xsrf_token)
        headers = {
        'Accept': 'application/json',
        'Accept-Language': 'vi',
        'Authorization': f'Bearer {self.auth_token}',
        'Connection': 'keep-alive',
        'Content-Type': 'application/json',
        'Lang': 'vi',
        'Origin': 'https://ocbomni.ocb.com.vn',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
        'X-Geo': '',
        'sec-ch-ua': '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        }

        self.load_cookies()
        # print(self.session.cookies)
        payload = json.dumps({
        "serviceAgreementId": self.serviceAgreementId
        })
        url = 'https://ocbomni.ocb.com.vn/api/access-control/client-api/v3/accessgroups/user-context'
        response = self.curl_post(url, headers=headers,data=payload,proxies=self.proxies)
        # print(response.cookies)
        self.save_cookies(response.cookies)
        # print('user_context',response,response.text)
        if response.status_code == 200:
            result = response.json()
            return result
        else:
            return None
    def get_info(self):
        if not self.serviceAgreementId:
            self.service_agreements()
            self.user_context()
        payload = {}
        headers = {
        'Accept': 'application/json',
        'Accept-Language': 'en-US,en;q=0.9',
        'Authorization': f'Bearer {self.auth_token}',
        'Connection': 'keep-alive',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
        'sec-ch-ua': '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
        }

        self.load_cookies()
        
        url = 'https://ocbomni.ocb.com.vn/api/arrangement-manager/client-api/v2/arrangement-views/account-overview/groups/current-account-vnd?_limit=100'
        response = self.curl_get(url, headers=headers,proxies=self.proxies)
        self.save_cookies(self.session.cookies)
        # print(response.status_code)
        # print(response.text)
        if response.status_code == 200:
            result = response.json()
            return result
        else:
            return None
    def arrangements(self):
        payload = json.dumps({
            "externalArrangementIds": [
                self.account_number
            ]
            })
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9,vi;q=0.8',
            'Connection': 'keep-alive',
            'Content-Type': 'application/json',
            'Host': 'onlinebanking.ocb.com.vn',
            'Referer': 'https://ocbomni.ocb.com.vn/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': self.user_agent,
            'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'Authorization': f'Bearer {self.auth_token}'
        }


        url = f'https://ocbomni.ocb.com.vn/api/sync-dis/client-api/v1/transactions/refresh/arrangements'
        self.load_cookies()
        response = self.curl_post(url, headers=headers, data=payload,proxies=self.proxies)
        self.save_cookies(self.session.cookies)
        return response
    def sync(self):
        payload = json.dumps({
        "types": [
            "ACCOUNT"
        ],
        "refreshAll": True
        })
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9,vi;q=0.8',
            'Connection': 'keep-alive',
            'Content-Type': 'application/json',
            'Host': 'onlinebanking.ocb.com.vn',
            'Referer': 'https://ocbomni.ocb.com.vn/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': self.user_agent,
            'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'Authorization': f'Bearer {self.auth_token}'
        }


        url = f'https://ocbomni.ocb.com.vn/api/bb-ingestion-service/client-api/v2/accounts/sync'
        self.load_cookies()
        response = self.curl_post(url, headers=headers, data=payload,proxies=self.proxies)
        self.save_cookies(self.session.cookies)
        return response
    def get_transactions(self, from_date="2022-11-15", to_date="2022-12-03",limit=100):
        list_transactions = []
        if limit > 500:
            page = limit//500
            for i in range(0,page+1):
                n_limit = 500
                item_transactions = self.get_transactions_by_page(from_date, to_date,n_limit,i)
                if len(item_transactions) == 0:
                    break
                list_transactions += item_transactions
        else:
            return self.get_transactions_by_page(from_date, to_date,limit,0)
         
        return list_transactions
            
    def get_session_and_code(self,url):
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Check if both 'session_state' and 'code' are in the query parameters
        if 'session_state' in query_params and 'code' in query_params:
            session_state = query_params['session_state'][0]
            code = query_params['code'][0]
            return (session_state, code)
        
        return (None,None)
            
    def get_transactions_by_page(self, from_date="2022-11-15", to_date="2022-12-03",limit=100,page=0):
        # res = self.sync()
        # res = self.arrangements()
        headers = {
        'Accept': 'application/json',
        'Accept-Language': 'vi',
        'Authorization': f'Bearer {self.auth_token}',
        'Connection': 'keep-alive',
        # 'Cookie': 'BIGipServer~Omni_4.0~Omni_4.0_Pool=175270410.20480.0000; _ga=GA1.1.569260134.1730308709; TS01f4a2ea=014bffbef0e3341402ddc29a65cf0264ff88421e42d8e0c2dbb79e9e247ca0b023dfe2585d140b5388c4a0309e464914e8d5c78730d37b2b1cbc7beeb5725b3d37be973167; TS01e1866a=014bffbef0ac0ab2c3626e75f199d10c105e034aa8ae77ddcd182d8f79a80268755ab4f90cccb8bb1c97e78cbd54692d47a3078576; USER_CONTEXT=eyJraWQiOiJaNXB5dkxcL3FMYUFyR3ZiTkY3Qm11UGVQU1Q4R0I5UHBPR0RvRnBlbmIxOD0iLCJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0..OTOdmkQAnoaPm5MsE1kDEw.gUS55wP5peyVWi9xIz2O49dO11Fi7XAo21E7z-iV8nJ12XOuT0Hn-kL7HK-XDfSAVmoZR-UiK76cGuH51kJu9bVbW0N3pJ1KQfxb8yuHwjXrqXzYswK0CmM_8WWq_tCqeVyKQKH1gvCbI9Hv8fzeOb2c21PnUUea-Y7GoR3cN_e5IPHOro3WGp6-N9D_4dby9hgxB_60fzZ1W2m4nL2qpMPuo0N3ISPvB87gTldQ-yVDZ472IriqcXtNoXTTIC4TsyaxD4dzCepEZ0mPcPCcTIBaS0_8_BZ1WD7Ia64Q4a_X6JpGfwg1Vj-s7CTZvM9d.EvUojthAum-N7i9faP-_tg; _ga_NJJ7PHJKV8=GS1.1.1730317030.3.1.1730317031.59.0.0; XSRF-TOKEN=9d57d065-5803-4d5e-a280-ef4f9f3e2404; TS01e1866a=014bffbef031e20e9fc98d327cfb58aef1091147abcd2693a28e811b6e902ebd34c56b1224a5e326e8c9fd2eebc07f1c91af336515',
        'Lang': 'vi',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
        'sec-ch-ua': '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
        }


        url = f'https://ocbomni.ocb.com.vn/api/transaction-manager/client-api/v2/transactions?bookingDateGreaterThan={from_date}&bookingDateLessThan={to_date}&arrangementId={self.id}&from={page}&size={limit}&orderBy=bookingDate&direction=DESC'
        self.load_cookies()
        response = self.curl_get(url, headers=headers,proxies=self.proxies)
        self.save_cookies(self.session.cookies)
        # with open("transaction"+str(page)+".html", "w", encoding="utf-8") as file:
        #     file.write(response.text)
        if response.status_code == 200:
            result = response.json()
            return result
        else:
            return {
            'success': False,
            'message': 'Please relogin!',
            'code': 401
        }

    def get_code_challenge(self, string):
        sha256_hash = hashlib.sha256(string.encode()).digest()
        base64_string = base64.b64encode(sha256_hash).decode()
        encrypted_string = base64_string.replace('+', '-').replace('/', '_').replace('=', '')
        return encrypted_string

    def is_json(self, string):
        try:
            json.loads(string)
            return True
        except json.JSONDecodeError:
            return False

    def get_microtime(self):
        return int(time.time() * 1000)

    def get_imei(self):
        time = hashlib.md5(str(self.get_microtime()).encode()).hexdigest()
        text = '-'.join([time[:8], time[8:12], time[12:16], time[16:20], time[17:]])
        text = text.upper()
        return text

    def get_user_agent(self):
        user_agent_array = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/604.3.5 (KHTML, like Gecko) Version/11.0.1 Safari/604.3.5",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.89 Safari/537.36 OPR/49.0.2725.47",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/604.4.7 (KHTML, like Gecko) Version/11.0.2 Safari/604.4.7",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.108 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36 Edge/15.15063",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
        "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.108 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36 OPR/49.0.2725.64",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.108 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/604.4.7 (KHTML, like Gecko) Version/11.0.2 Safari/604.4.7",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/62.0.3202.94 Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0;  Trident/5.0)",
        "Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/63.0.3239.84 Chrome/63.0.3239.84 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
        "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.108 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.89 Safari/537.36",
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0;  Trident/5.0)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.8",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/604.3.5 (KHTML, like Gecko) Version/11.0.1 Safari/604.3.5",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.8",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:58.0) Gecko/20100101 Firefox/58.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Safari/604.1.38",
        "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (X11; CrOS x86_64 9901.77.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.97 Safari/537.36"
                        ]
        return random.choice(user_agent_array)
    def check_bank_name_in(self, ben_account_number):
        headers = {
        'Accept': 'application/json',
        'Accept-Language': 'vi',
        'Authorization': f'Bearer {self.auth_token}',
        'Connection': 'keep-alive',
        'Cookie': 'BIGipServer~Omni_4.0~Omni_4.0_Pool=175270410.20480.0000; _ga=GA1.1.569260134.1730308709; TS01f4a2ea=014bffbef0e3341402ddc29a65cf0264ff88421e42d8e0c2dbb79e9e247ca0b023dfe2585d140b5388c4a0309e464914e8d5c78730d37b2b1cbc7beeb5725b3d37be973167; TS01e1866a=014bffbef0ac0ab2c3626e75f199d10c105e034aa8ae77ddcd182d8f79a80268755ab4f90cccb8bb1c97e78cbd54692d47a3078576; USER_CONTEXT=eyJraWQiOiJaNXB5dkxcL3FMYUFyR3ZiTkY3Qm11UGVQU1Q4R0I5UHBPR0RvRnBlbmIxOD0iLCJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0..OTOdmkQAnoaPm5MsE1kDEw.gUS55wP5peyVWi9xIz2O49dO11Fi7XAo21E7z-iV8nJ12XOuT0Hn-kL7HK-XDfSAVmoZR-UiK76cGuH51kJu9bVbW0N3pJ1KQfxb8yuHwjXrqXzYswK0CmM_8WWq_tCqeVyKQKH1gvCbI9Hv8fzeOb2c21PnUUea-Y7GoR3cN_e5IPHOro3WGp6-N9D_4dby9hgxB_60fzZ1W2m4nL2qpMPuo0N3ISPvB87gTldQ-yVDZ472IriqcXtNoXTTIC4TsyaxD4dzCepEZ0mPcPCcTIBaS0_8_BZ1WD7Ia64Q4a_X6JpGfwg1Vj-s7CTZvM9d.EvUojthAum-N7i9faP-_tg; _ga_NJJ7PHJKV8=GS1.1.1730317030.3.1.1730317031.59.0.0; XSRF-TOKEN=9d57d065-5803-4d5e-a280-ef4f9f3e2404; TS01e1866a=014bffbef031e20e9fc98d327cfb58aef1091147abcd2693a28e811b6e902ebd34c56b1224a5e326e8c9fd2eebc07f1c91af336515',
        'Lang': 'vi',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
        'sec-ch-ua': '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
        }


        url = f'https://ocbomni.ocb.com.vn/api/account-integration-service/client-api/v1/accounts/inquiry-accounts'
        data = {
            'accountOrPhone': ben_account_number,
            'transferType':'INTERNAL_TRANSFER'
        }
        self.load_cookies()
        response = self.curl_post(url,headers=headers, data=data,proxies=self.proxies)
        self.save_cookies(self.session.cookies)
        # with open("transaction"+str(page)+".html", "w", encoding="utf-8") as file:
        #     file.write(response.text)
        if response.status_code == 200:
            result = response.json()
            return result
        else:
            return {
            'success': False,
            'message': 'Please relogin!',
            'code': 401,
            'data':response.json()
        }
    def mapping_bank_code(self,bank_name):
        with open('banks.json','r', encoding='utf-8') as f:
            data = json.load(f)
        for bank in data['data']:
            if bank['shortName'].lower() == bank_name.lower():
                return bank['bin']
    def mapping_bank_code_ocb(self,bank_name):
        with open('banks.json','r', encoding='utf-8') as f:
            data = json.load(f)
        for bank in data['data']:
            if bank['shortName'].lower() == bank_name.lower():
                with open('ocb.json','r', encoding='utf-8') as f:
                    data_2 = json.load(f)
                for bank_2 in data_2:
                    if bank_2['napasBankCode'] == bank['bin']:
                        return bank_2['coreBankId']
    def check_bank_name_out(self, ben_account_number,bank_name):
        bank_code = self.mapping_bank_code(bank_name)
        coreBankId = self.mapping_bank_code_ocb(bank_name)
        headers = {
        'Accept': 'application/json',
        'Accept-Language': 'vi',
        'Authorization': f'Bearer {self.auth_token}',
        'Connection': 'keep-alive',
        'Content-Type': 'application/json',
        'Lang': 'vi',
        'Origin': 'https://ocbomni.ocb.com.vn',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
        'X-XSRF-TOKEN': 'e5a10522-01d1-4aec-9fe7-7b2983171411',
        'sec-ch-ua': '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
        }


        url = f'https://ocbomni.ocb.com.vn/api/account-integration-service/client-api/v1/accounts/inquiry-accounts'
        data = json.dumps({
            'accountOrPhone': ben_account_number,
            'bankCode':bank_code,
            'coreBankId':coreBankId,
            'transferType':'NAPAS_ACCOUNT_NUMBER'
        })
        response = requests.post(url,headers=headers, data=data,proxies=self.proxies)

        if response.status_code == 200:
            result = response.json()
            return result
        else:
            return {
            'success': False,
            'message': 'Please relogin!',
            'code': 401
        }
    def convert_to_uppercase_no_accents(self,text):
        # Remove accents
        no_accents = unidecode.unidecode(text)
        # Convert to uppercase
        return no_accents.upper()
    def get_bank_name(self, ben_account_number, bank_name):
        self.do_refresh_token()
        
        if bank_name == 'OCB':
            result =  self.check_bank_name_in(ben_account_number)
        else:
            result =  self.check_bank_name_out(ben_account_number,bank_name)
        if 'accountHolderName' not in result:
            print(result)
            return self.login_ocb(ben_account_number, bank_name)
        return result
    def check_bank_name(self,ben_account_number, bank_name, ben_account_name):
        get_name_from_account = self.get_bank_name(ben_account_number, bank_name)
        print('get_name_from_account_ocb',get_name_from_account)
        if 'accountHolderName' in get_name_from_account:
            input_name = self.convert_to_uppercase_no_accents(ben_account_name).lower().strip()
            output_name = get_name_from_account['accountHolderName'].lower().strip()
            if output_name == input_name or output_name.strip().replace(' ','') == input_name.strip().replace(' ',''):
                return True
            else:
                return output_name
        return False
    def login_ocb(self,ben_account_number=None, bank_name=None):
        login = self.do_login()
        if login and 'success' in login and login['success']:
            print('waiting')
            if 'waiting' in login and login['waiting']:
                url = login['url']
                i = 1
                status = "PENDING"
                while True:
                    if i >= 60:
                        return {
                            'code':408,
                            'message':'Time out confirm!',
                        }
                    cr = self.check_session(url)
                    if self.is_json(cr):
                        check = json.loads(cr)
                        url = check['actionUrl']
                        status = check['status']
                        if status == "PENDING":
                            time.sleep(2)
                        else:
                            print('login success')
                            break
                    i += 1
            elif 'session_state' in login:
                print('login success')
                session_state = login['session_state']
                code = login['code']
            else:
                print('login success')
        else:
            return login
        if not code:
            continue_check = self.continue_check_session(url)
                # Extract the code from the URL
            code = continue_check.split('code=')[1]
        try:
            token = self.get_token(code, "https://ocbomni.ocb.com.vn/en-US/select-context")
            if token:
                return self.get_bank_name(ben_account_number, bank_name)
            else:
                return None
        except Exception as e:
            return None

def loginOCB(user):
    session_state,code = None,None
    refresh_token = user.do_refresh_token()
    if 'access_token' not in refresh_token:
        login = user.do_login()
        print('login',login)
        if login and 'success' in login and login['success']:
            if 'waiting' in login and login['waiting']:
                url = login['url']
                i = 1
                status = "PENDING"
                while True:
                    if i >= 60:
                        return {
                            'code':408,
                            'message':'Time out confirm!',
                        }
                    cr = user.check_session(url)
                    if user.is_json(cr):
                        check = json.loads(cr)
                        url = check['actionUrl']
                        status = check['status']
                        if status == "PENDING":
                            time.sleep(2)
                        else:
                            print('login success')
                            break
                    i += 1
            elif 'session_state' in login:
                print('login success')
                session_state = login['session_state']
                code = login['code']
            else:
                print('login success')
        else:
            return login
        if not code:
            continue_check = user.continue_check_session(url)
                # Extract the code from the URL
            code = continue_check.split('code=')[1]
        try:
            token = user.get_token(code, "https://ocbomni.ocb.com.vn/en-US/select-context")
            if token:
                result = sync_balance_ocb(user)
                result['message'] = 'Đăng nhập thành công'
                return(result)
            else:
                return(0)
        except Exception as e:
            return(e)
    else:
        result = sync_balance_ocb(user)
        result['message'] = 'Đăng nhập thành công'
        return(result)
    


def sync_balance_ocb(user):
    ary_info = user.get_info()
    # print('ary_info',ary_info)
    if ary_info:
        for element in ary_info.get("elements", []):
            if element["attributes"]["bban"]["value"] == user.account_number:
                user.balance =  int(element["attributes"]["availableBalance"]["value"])
                user.id = (element["id"])
                user.save_data()
                return {
                    'success': True,
                    'data':{
                        'balance': user.balance,
                    },
                    'code': 200
                }
    return {
            'success': False,
            'message': 'Please relogin!',
            'code': 401
            }

def sync_ocb(user, start, end,limit):
    user.do_refresh_token()
    ary_data = user.get_transactions(start, end,limit)
    # print(ary_data)
    if not ary_data:
        return {
            'success': True,
            'message': 'Không tìm thấy lịch sử giao dịch',
            'code': 200
        }
    if ('code' in ary_data and ary_data['code'] == 401) or ('error' in ary_data and ary_data['error'] == 'Unauthorized'):
        return {
            'success': False,
            'message': 'Please relogin!',
            'code': 401
        }


    return {
        'success': True,
        'message': 'Thành công',
        'data': ary_data,
        'code': 200
    }


def refresh_token_user(user):
    return user.do_refresh_token()
def get_key_pos_number(number):
    line = (number - 1) // 3 + 1
    pos = (number - 1) % 3 + 1
    return f"{line}_{pos}"
# if __name__ == '__main__':
    # Example usage of the OCB class
    # while True:
        # user = OCB("0338549217", "Matkhau123123@", "9338549517", "")
        # # user = OCB("0358027860", "Dinh5500@", "19033744815017", "")

        # #un comment login for first time, after that just call sync_balance_ocb or sync_ocb

        # loginOCB(user)

        # balance = sync_balance_ocb(user)
        # print(balance)
        # transactions = sync_ocb(user,"2024-04-01","2024-04-04",10000000)
        # print(transactions)
        # file_path = "output_tcb_04.04.json"
        # with open(file_path, 'w') as json_file:
        #     json.dump(transactions, json_file, indent=4)

        # print(f"JSON data has been saved to {file_path}")
        # time.sleep(30)