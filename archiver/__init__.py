from base64 import b64decode
from datetime import datetime
from gzip import GzipFile
from io import BytesIO
import json
import math
import os
import re
from time import sleep, time
import urllib
import uuid
import boto3
from kubernetes import client, config
import pytz
import requests
import tldextract
from mitmproxy import http
from .data import INVALID_REQUESTS
from .har import HarBuilder
from .javascript import JAVASCRIPT_MAIN_CODE, JAVASCRIPT_IFRAME_CODE


AUTO_CRAWL_SCHEME = os.environ.get('MITM_PROXY_AUTO_CRAWL_SCHEME', 'http')
AUTO_CRAWL_HOST = os.environ.get('MITM_PROXY_AUTO_CRAWL_HOST', '127.0.0.1:8000')
HTML2CANVAS_PROXY_SCHEME = os.environ.get('MITM_PROXY_HTML2CANVAS_PROXY_SCHEME', 'http')
HTML2CANVAS_PROXY_HOST = os.environ.get('MITM_PROXY_HTML2CANVAS_PROXY_HOST', ', 127.0.0.1:3000')
PROXY_PHONE_HOME_PATH = '/auto-crawl/proxy-phone-home-cfbd0f41bf9c48c499f5995c518aac86/'
INFORM_OF_IDENTIFIED_FLOW_PATH = '/auto-crawl/inform-of-identified-flow-e2efe8ad36694eb3944382db0377817e/'
UPDATE_FRAMES_PATH = '/auto-crawl/update-902b4684bf124ebdab893f97323d35d8/'
UPDATE_FRAMES_REGEX = re.compile(re.escape(AUTO_CRAWL_SCHEME + '://' + AUTO_CRAWL_HOST + UPDATE_FRAMES_PATH))
FORCE_SAVE_STATE_REGEX = re.compile(re.escape(AUTO_CRAWL_SCHEME + '://' + AUTO_CRAWL_HOST + '/auto-crawl/force-save-state/'))
FORCE_DUMP_STATE_REGEX = re.compile(re.escape(AUTO_CRAWL_SCHEME + '://' + AUTO_CRAWL_HOST + '/auto-crawl/force-dump-state/'))
REMOTE_FORCE_SAVE_STATE_REGEX = re.compile('http://0cab400a183048a6a995a6fefeff3795\.com')
REMOTE_FORCE_DUMP_STATE_REGEX = re.compile('http://f9730d272bff468eb2c027e6d4dcf81f\.com')
REMOTE_UPDATE_FRAMES_REGEX = re.compile('/d33c238b8a2941c8b7d351b72ba9be38')
REDIRECT_DETECTED_REGEX = re.compile('/ec8d334e85084245940a97e127a8ff81')
HTML2CANVAS_PROXY_REGEX = re.compile('/ed761adff5e24dbc93a5b05147161c94')
SCREENSHOT_SAVE_REGEX = re.compile('/6fc356938f124cc0b23902773f6c495b')
S3_SIGNATURES_BUCKET = os.environ.get('MITM_SIGNATURES_BUCKET', 'mitm-signatures')
S3_SIGNATURES_FILE = os.environ.get('MITM_SIGNATURES_FILE', 'signatures.json')
S3_OUTPUT_BUCKET = os.environ.get('MITM_OUTPUT_BUCKET', 'mitm-archive')
JAVASCRIPT_SEARCH = re.compile(b'</body>')
UTC_TIMEZONE = pytz.timezone('UTC')
S3_CLIENT = boto3.client('s3')
HTML_CONTENT_TYPE = re.compile('text/html')
JAVASCRIPT_CONTENT_TYPE = re.compile('application/javascript')
JSON_CONTENT_TYPE = re.compile('application/json')
KUBERNETES_NAMESPACE = os.environ.get('MITM_PROXY_KUBERNETES_NAMESPACE', 'default')
KUBERNETES_SERVICE_NAME = os.environ.get('MITM_PROXY_KUBERNETES_SERVICE_NAME')
if not KUBERNETES_SERVICE_NAME:
    KUBERNETES_SERVICE_NAME = os.environ.get('HOSTNAME')
    if KUBERNETES_SERVICE_NAME:
        KUBERNETES_SERVICE_NAME = '-'.join(KUBERNETES_SERVICE_NAME.split('-')[:-2])


class Archiver:

    def __init__(self):
        # Proxy attributes
        self.proxy_session_id = str(uuid.uuid4()).replace('-', '')
        self.code_inject_mode = 'inactive'
        self.page_wait_time = 60
        self.active = False
        self.active_time = None
        self.last_page_load_source = 'scan'
        # Page load attributes
        self.page_session_id = str(uuid.uuid4()).replace('-', '')
        self.target_url = None
        self.target_registered_domain = None
        self.redirected_target_url = None
        self.redirected_target_registered_domain = None
        self.har_client = None
        self.payload_count = 0
        self.archive = False
        self.archive_path = None
        self.archive_time = None
        self.identified_flows = []
        self.screenshots_saved = 0
        self.metadata = {}
        self.signatures = []
        self.main_code_injected = False
        # Auto crawl attributes
        self.auto_crawl_session_id = None
        self.auto_crawl_device_name = None
        # Kubernetes
        self.kubernetes_service_endpoint = 'unknown'
        self.kubernetes_service_port = 'unknown'

    # Helper methods
    def retrieve_kubernetes_service_data(self):
        if KUBERNETES_NAMESPACE and KUBERNETES_SERVICE_NAME:
            config.load_incluster_config()
            v1 = client.CoreV1Api()
            loops = 1
            while self.kubernetes_service_endpoint == 'unknown' and self.kubernetes_service_port == 'unknown' and \
                    loops <= 10:
                try:
                    r = v1.read_namespaced_service(KUBERNETES_SERVICE_NAME, KUBERNETES_NAMESPACE)
                    service_dict = r.to_dict()
                    self.kubernetes_service_endpoint = service_dict['status']['load_balancer']['ingress'][0]['hostname']
                    self.kubernetes_service_port = service_dict['spec']['ports'][0]['port']
                except Exception as e:
                    sleep(30)
                    loops += 1

    def set_archive_metadata(self):
        target_registered_domain = self.target_registered_domain if self.target_registered_domain else 'no-site'
        self.archive_time = self.archive_time or datetime.now().astimezone(UTC_TIMEZONE)
        self.archive_path = f'{self.archive_time.year}/{self.archive_time.month}/{self.archive_time.day}/' + \
                            f'{self.archive_time.hour}/{target_registered_domain}/{self.page_session_id}/'

    def archive_har_data(self, dump_key='main.har'):
        if not self.archive_path:
            self.set_archive_metadata()
        archive_path = self.archive_path + dump_key
        metadata = {
            '_proxy_session_id': self.proxy_session_id,
            '_page_session_id': self.page_session_id,
            '_code_inject_mode': self.code_inject_mode,
            '_page_wait_time': self.page_wait_time,
            '_target_url': self.target_url,
            '_target_registered_domain': self.target_registered_domain,
            '_redirected_target_url': self.redirected_target_url,
            '_redirected_registered_domain': self.redirected_target_registered_domain,
            '_auto_crawl_session_id': self.auto_crawl_session_id,
            '_auto_crawl_device_name': self.auto_crawl_device_name,
            '_archive_time_utc': self.archive_time.strftime('%Y-%m-%d %H:%M:%S.%f'),
            '_identified_flows': self.identified_flows,
            '_screenshots_saved': self.screenshots_saved,
            **self.metadata,
        }
        self.har_client.add_metadata(metadata)
        data = json.dumps(self.har_client.har_data, indent=2)
        gz_body = BytesIO()
        gz = GzipFile(None, 'wb', 9, gz_body)
        gz.write(data.encode('utf-8'))
        gz.close()
        S3_CLIENT.put_object(Body=gz_body.getvalue(), ContentType='text/plain', ContentEncoding='gzip',
                             Bucket=S3_OUTPUT_BUCKET, Key=archive_path)

    def retrieve_signatures(self):
        result = S3_CLIENT.get_object(Bucket=S3_SIGNATURES_BUCKET, Key=S3_SIGNATURES_FILE)
        signatures = json.loads(result['Body'].read().decode('utf-8'))['signatures']
        self.signatures = [{
            'signature_id': signature['signature_id'],
            'match_type': signature['match_type'],
            'match_value': re.compile(signature['match_value']),
            'date_created': signature['date_created'],
        } for signature in signatures]

    def reset_proxy_state(self):
        self.active = True
        self.active_time = time()
        self.page_session_id = str(uuid.uuid4()).replace('-', '')
        self.target_url = None
        self.target_registered_domain = None
        self.redirected_target_url = None
        self.redirected_target_registered_domain = None
        self.har_client = HarBuilder()
        self.payload_count = 0
        self.archive = False
        self.archive_path = None
        self.archive_time = None
        self.identified_flows = []
        self.screenshots_saved = 0
        self.metadata = {}
        self.retrieve_signatures()
        self.main_code_injected = False

    # Request methods
    def check_active(self):
        if self.active:
            if time() - self.active_time > int(self.page_wait_time) * 10:
                self.active = False

    def handle_remote_save_state_instruction(self, flow):
        if not self.archive:
            self.set_archive_metadata()
            self.archive = True
        self.metadata.update({'_remote_save_state_forced': True})
        flow.response = http.HTTPResponse.make(200, '{{"status": "success", "archive-path": "{}"}}'.\
                                                    format(self.archive_path).encode('utf-8'),
                                               {'Content-Type': 'text/plain'})

    def handle_remote_dump_state_instruction(self, flow):
        if not self.archive:
            self.set_archive_metadata()
            self.archive = True
        self.metadata.update({'_remote_save_state_forced': True})
        self.metadata.update({'_remote_dump_state_forced': True})
        self.archive_har_data(dump_key='{}.har'.format(str(uuid.uuid4()).replace('-', '')))
        flow.response = http.HTTPResponse.make(200, '{{"status": "success", "archive-path": "{}"}}'. \
                                                    format(self.archive_path).encode('utf-8'),
                                               {'Content-Type': 'text/plain'})

    def identify_behavioral_redirect(self, flow):
        if not self.archive:
            self.set_archive_metadata()
            self.archive = True
            parameters = urllib.parse.urlencode({
                'auto-crawl-session-id': self.auto_crawl_session_id,
                'page-session-id': self.page_session_id,
                'archive-path': self.archive_path,
                'redirect-detected': True,
            })
            requests.get(AUTO_CRAWL_SCHEME + '://' + AUTO_CRAWL_HOST + INFORM_OF_IDENTIFIED_FLOW_PATH + '?' + parameters)
        self.metadata.update({'_behavioral_redirect_detected': True})
        if flow.request.query.get('flow-id'):
            self.metadata['_behavioral_redirect_flows'] = self.metadata.get('_behavioral_redirect_flows', []) + \
                                                          [flow.request.query.get('flow-id')]
        flow.response = http.HTTPResponse.make(200, b'Behavioral redirect logged', {'Content-Type': 'text/plain'})

    def route_html2canvas_proxy(self, flow):
        if flow.request.query.get('url'):
            parameters = urllib.parse.urlencode({
                'url': flow.request.query['url'],
            })
            r = requests.get(HTML2CANVAS_PROXY_SCHEME + '://' + HTML2CANVAS_PROXY_HOST + '?' + parameters)
            if r.status_code == 200:
                flow.response = http.HTTPResponse.make(200, r.content, {'Content-Type': 'text/html; charset=utf-8'})
            else:
                flow.response = http.HTTPResponse.make(200, ''.encode('utf-8'),
                                                       {'Content-Type': 'text/html; charset=utf-8'})
        else:
            flow.response = http.HTTPResponse.make(200, ''.encode('utf-8'),
                                                   {'Content-Type': 'text/html; charset=utf-8'})

    def save_screenshot(self, flow):
        if not self.archive:
            self.set_archive_metadata()
            self.archive = True
        self.screenshots_saved += 1
        archive_path = self.archive_path + f'images/{self.screenshots_saved:03}.png'
        image = BytesIO(b64decode(flow.request.content.decode('utf-8').split(',')[1]))
        S3_CLIENT.put_object(Body=image.getvalue(), ContentType='image/png', Bucket=S3_OUTPUT_BUCKET, Key=archive_path)
        flow.response = http.HTTPResponse.make(200, b'Screenshot save successful', {'Content-Type': 'text/plain'})

    def process_new_page_load_request(self, flow):
        if self.active_time and flow.request.query.get('source') and \
                flow.request.query['source'] == 'scan' and \
                time() - self.active_time < int(self.page_wait_time) * 2:
            flow.request.query['previous-page-payload-count'] = self.payload_count
            flow.request.query['proxy-session-id'] = self.proxy_session_id
            flow.request.query['page-session-id'] = self.page_session_id
            flow.request.query['waiting-status'] = 'true'
        else:
            self.last_page_load_source = 'scan'
            flow.request.query['previous-page-payload-count'] = self.payload_count
            flow.request.query['proxy-session-id'] = self.proxy_session_id
            flow.request.query['page-session-id'] = self.page_session_id
            self.auto_crawl_session_id = flow.request.query.get('auto-crawl-session-id')
            self.auto_crawl_device_name = flow.request.query.get('auto-crawl-device-name')
            self.code_inject_mode = flow.request.query.get('inject-javascript-mode') or self.code_inject_mode
            self.page_wait_time = flow.request.query.get('page-wait-time') or self.page_wait_time

    def process_new_remote_page_load_request(self, flow):
        self.last_page_load_source = 'remote'
        parameters = urllib.parse.urlencode({
            'auto-crawl-session-id': self.auto_crawl_session_id,
            'auto-crawl-device-name': self.auto_crawl_device_name,
            'source': 'remote',
            'inject-javascript-mode': self.code_inject_mode,
            'page-wait-time': self.page_wait_time,
            'previous-page-payload-count': self.payload_count,
            'proxy-session-id': self.proxy_session_id,
            'page-session-id': self.page_session_id,
        })
        if self.active_time and time() - self.active_time < math.ceil(int(self.page_wait_time) * 0.8):
            parameters += '&' + urllib.parse.urlencode({'waiting-status': 'true'})
        r = requests.get(AUTO_CRAWL_SCHEME + '://' + AUTO_CRAWL_HOST + UPDATE_FRAMES_PATH + '?' + parameters)
        if r.status_code == 200:
            try:
                response_content = r.json()
                if response_content['status'] == 'success':
                    if self.archive:
                        self.archive_har_data()
                    self.reset_proxy_state()
                    self.target_url = response_content['targetURL']
                    self.target_registered_domain = tldextract.extract(self.target_url).registered_domain
            except Exception as e:
                pass
        flow.response = http.HTTPResponse.make(200, r.content, {'Content-Type': 'application/json'})
        flow.response.timestamp_start = flow.request.timestamp_start
        flow.response.timestamp_end = flow.request.timestamp_end

    # Response methods
    def process_new_page_load_response(self, flow):
        try:
            response_content = json.loads(flow.response.content.decode('utf-8', errors='ignore'))
            if response_content['status'] == 'success':
                if self.archive:
                    self.archive_har_data()
                self.reset_proxy_state()
                self.target_url = response_content['targetURL']
                self.target_registered_domain = tldextract.extract(self.target_url).registered_domain
        except Exception as e:
            pass

    @staticmethod
    def check_valid_flow(flow):
        for pattern in INVALID_REQUESTS:
            if pattern['match_type'] == 'host':
                if re.search(pattern['match_value'], flow.request.host):
                    return False
            elif pattern['match_type'] == 'path':
                if re.search(pattern['match_value'], flow.request.path):
                    return False
            elif pattern['match_type'] == 'url':
                if re.search(pattern['match_value'], flow.request.url):
                    return False
        return True

    def check_signatures(self, flow):
        for signature in self.signatures:
            if signature['match_type'] == 'host':
                if re.search(signature['match_value'], flow.request.host):
                    self.identify_flow(signature)
                    break
            elif signature['match_type'] == 'path':
                if re.search(signature['match_value'], flow.request.path):
                    self.identify_flow(signature)
                    break
            elif signature['match_type'] == 'url':
                if re.search(signature['match_value'], flow.request.url):
                    self.identify_flow(signature)
                    break
            elif signature['match_type'] == 'response_content':
                response_content_type = flow.response.headers.get('Content-Type')
                if response_content_type and (re.search(HTML_CONTENT_TYPE, response_content_type) or
                        re.search(JAVASCRIPT_CONTENT_TYPE, response_content_type) or
                        re.search(JSON_CONTENT_TYPE, response_content_type)):
                    if re.search(signature['match_value'], flow.response.content.decode('utf-8', errors='ignore')):
                        self.identify_flow(signature)
                        break

    def identify_flow(self, signature):
        self.identified_flows.append({
            'signature_id': signature['signature_id'],
            'match_type': signature['match_type'],
            'match_value': signature['match_value'].pattern,
            'signature_date_created': signature['date_created'],
            'flow_number': self.payload_count,
        })
        if not self.archive:
            self.set_archive_metadata()
            parameters = urllib.parse.urlencode({
                'auto-crawl-session-id': self.auto_crawl_session_id,
                'page-session-id': self.page_session_id,
                'archive-path': self.archive_path,
            })
            requests.get(AUTO_CRAWL_SCHEME + '://' + AUTO_CRAWL_HOST + INFORM_OF_IDENTIFIED_FLOW_PATH + '?' + parameters)
            self.archive = True

    def inject_javascript_controller(self, flow):
        if (self.redirected_target_url and self.redirected_target_registered_domain and
                self.redirected_target_registered_domain in flow.request.host) or \
                self.target_registered_domain in flow.request.host:
            if str(flow.response.status_code)[0] == '3':
                self.redirected_target_url = flow.response.headers.get('Location')
                self.redirected_target_registered_domain = tldextract.extract(self.redirected_target_url).\
                                                                      registered_domain
            elif 'text/html' in flow.response.headers.get('Content-Type', ''):
                self.inject_javascript_main(flow)
        elif 'text/html' in flow.response.headers.get('Content-Type', ''):
            self.inject_javascript_iframe(flow)

    def inject_javascript_main(self, flow):
        if self.main_code_injected:
            self.metadata.update({'_page_refresh_detected': True})
            page_wait_time = math.ceil(int(self.page_wait_time) * 1000 * 1.2)
        else:
            page_wait_time = int(self.page_wait_time) * 1000
        flow.response.content = \
            JAVASCRIPT_SEARCH.sub(JAVASCRIPT_MAIN_CODE.format(page_wait_time).encode(encoding='utf-8') + b'</body>',
                                  flow.response.content, count=1)
        self.metadata.update({'_main_code_injected': True})
        self.main_code_injected = True

    def inject_javascript_iframe(self, flow):
        page_wait_time = math.ceil(int(self.page_wait_time) * 1000 * 1.5)
        proxy_url = flow.request.scheme + '://' + flow.request.host
        flow.response.content = \
            JAVASCRIPT_SEARCH.sub(JAVASCRIPT_IFRAME_CODE.format(self.payload_count, proxy_url, page_wait_time).
                                                         encode(encoding='utf-8') + b'</body>',
                                  flow.response.content, count=1)
        self.metadata.update({'_iframe_code_injected': True})

    def archive_flow(self, flow):
        self.har_client.update_har_data_from_response(flow)

    # Proxy methods
    def request(self, flow: http.HTTPFlow) -> None:
        self.check_active()
        if re.search(REMOTE_FORCE_SAVE_STATE_REGEX, flow.request.url):
            self.handle_remote_save_state_instruction(flow)
        elif re.search(REMOTE_FORCE_DUMP_STATE_REGEX, flow.request.url):
            self.handle_remote_dump_state_instruction(flow)
        elif re.search(REDIRECT_DETECTED_REGEX, flow.request.path):
            self.identify_behavioral_redirect(flow)
        elif re.search(HTML2CANVAS_PROXY_REGEX, flow.request.url):
            self.route_html2canvas_proxy(flow)
        elif re.search(SCREENSHOT_SAVE_REGEX, flow.request.path):
            self.save_screenshot(flow)
        elif re.search(FORCE_SAVE_STATE_REGEX, flow.request.url):
            self.metadata.update({'_save_state_forced': True})
            self.set_archive_metadata()
            self.archive = True
            flow.request.query['archive-path'] = self.archive_path
        elif re.search(FORCE_DUMP_STATE_REGEX, flow.request.url):
            self.metadata.update({'_save_state_forced': True})
            self.metadata.update({'_dump_state_forced': True})
            self.set_archive_metadata()
            self.archive = True
            self.archive_har_data(dump_key='{}.har'.format(str(uuid.uuid4()).replace('-', '')))
            flow.request.query['archive-path'] = self.archive_path
        elif flow.request.method != 'OPTIONS' and re.search(UPDATE_FRAMES_REGEX, flow.request.url):
            self.process_new_page_load_request(flow)
        elif re.search(REMOTE_UPDATE_FRAMES_REGEX, flow.request.path):
            self.process_new_remote_page_load_request(flow)
        else:
            flow.request.headers.pop('If-Modified-Since', None)
            flow.request.headers.pop('If-None-Match', None)

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.request.method != 'OPTIONS' and re.search(UPDATE_FRAMES_REGEX, flow.request.url):
            self.process_new_page_load_response(flow)
        if self.active:
            valid = self.check_valid_flow(flow)
            if valid:
                self.payload_count += 1
                self.check_signatures(flow)
                if self.code_inject_mode != 'inactive':
                    self.inject_javascript_controller(flow)
                self.archive_flow(flow)

    def load(self, loader):
        self.retrieve_kubernetes_service_data()
        parameters = urllib.parse.urlencode({
            'status': 'up',
            'proxy-session-id': self.proxy_session_id,
            'endpoint': self.kubernetes_service_endpoint,
            'port': self.kubernetes_service_port,
        })
        requests.get(AUTO_CRAWL_SCHEME + '://' + AUTO_CRAWL_HOST + PROXY_PHONE_HOME_PATH + '?' + parameters)

    def done(self):
        parameters = urllib.parse.urlencode({
            'status': 'down',
            'proxy-session-id': self.proxy_session_id,
        })
        requests.get(AUTO_CRAWL_SCHEME + '://' + AUTO_CRAWL_HOST + PROXY_PHONE_HOME_PATH + '?' + parameters)
