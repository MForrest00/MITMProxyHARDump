import base64
from datetime import datetime, timezone
# import re
import typing
from mitmproxy import connections
from mitmproxy import version
from mitmproxy.net.http import cookies
from mitmproxy.utils import strutils
# from .data import ADJUSTED_FLOWS


def format_cookies(cookie_list):
    rv = []
    for name, value, attrs in cookie_list:
        cookie_har = {
            'name': name,
            'value': value,
        }
        for key in ['path', 'domain', 'comment']:
            if key in attrs:
                cookie_har[key] = attrs[key]
        for key in ['httpOnly', 'secure']:
            cookie_har[key] = bool(key in attrs)
        expire_ts = cookies.get_expiration_ts(attrs)
        if expire_ts is not None:
            cookie_har['expires'] = datetime.fromtimestamp(expire_ts, timezone.utc).isoformat()
        rv.append(cookie_har)
    return rv


def format_request_cookies(fields):
    return format_cookies(cookies.group_cookies(fields))


def format_response_cookies(fields):
    return format_cookies((c[0], c[1][0], c[1][1]) for c in fields)


def name_value(obj):
    return [{'name': k, 'value': v} for k, v in obj.items()]


class HarBuilder:

    def __init__(self):
        self.har_data: typing.Dict = {}
        self.servers_seen: typing.Set[connections.ServerConnection] = set()
        self.configure_har_data()

    def configure_har_data(self):
        self.har_data.update({
            'log': {
                'version': '1.2',
                'creator': {
                    'name': 'mitmproxy har_dump',
                    'version': '0.1',
                    'comment': 'mitmproxy version {}'.format(version.MITMPROXY),
                },
                'entries': []
            }
        })

    # @staticmethod
    # def adjust_flow(flow):
    #     for pattern in ADJUSTED_FLOWS:
    #         if pattern['match_type'] == 'host':
    #             if re.search(pattern['match_value'], flow.request.host):
    #                 return pattern['adjustment_method']
    #         elif pattern['match_type'] == 'path':
    #             if re.search(pattern['match_value'], flow.request.path):
    #                 return pattern['adjustment_method']
    #         elif pattern['match_type'] == 'url':
    #             if re.search(pattern['match_value'], flow.request.url):
    #                 return pattern['adjustment_method']
    #         elif pattern['match_type'] == 'content_type':
    #             if re.search(pattern['match_value'], flow.response.headers.get('Content-Type', '')):
    #                 return pattern['adjustment_method']
    #     return None

    def update_har_data_from_response(self, flow):
        ssl_time = -1
        connect_time = -1
        if flow.server_conn and flow.server_conn not in self.servers_seen:
            connect_time = (flow.server_conn.timestamp_tcp_setup - flow.server_conn.timestamp_start)
            if flow.server_conn.timestamp_tls_setup is not None:
                ssl_time = (flow.server_conn.timestamp_tls_setup - flow.server_conn.timestamp_tcp_setup)
            self.servers_seen.add(flow.server_conn)
        timings_raw = {
            'send': flow.request.timestamp_end - flow.request.timestamp_start,
            'receive': flow.response.timestamp_end - flow.response.timestamp_start,
            'wait': flow.response.timestamp_start - flow.request.timestamp_end,
            'connect': connect_time,
            'ssl': ssl_time,
        }
        timings = dict([(k, int(1000 * v)) for k, v in timings_raw.items()])
        full_time = sum(v for v in timings.values() if v > -1)
        started_date_time = datetime.fromtimestamp(flow.request.timestamp_start, timezone.utc).isoformat()
        response_body_size = len(flow.response.raw_content)
        response_body_decoded_size = len(flow.response.content)
        response_body_compression = response_body_decoded_size - response_body_size
        entry = {
            'startedDateTime': started_date_time,
            'time': full_time,
            'request': {
                'method': flow.request.method,
                'url': flow.request.url,
                'httpVersion': flow.request.http_version,
                'cookies': format_request_cookies(flow.request.cookies.fields),
                'headers': name_value(flow.request.headers),
                'queryString': name_value(flow.request.query or {}),
                'headersSize': len(str(flow.request.headers)),
                'bodySize': len(flow.request.content),
            },
            'response': {
                'status': flow.response.status_code,
                'statusText': flow.response.reason,
                'httpVersion': flow.response.http_version,
                'cookies': format_response_cookies(flow.response.cookies.fields),
                'headers': name_value(flow.response.headers),
                'content': {
                    'size': response_body_size,
                    'compression': response_body_compression,
                    'mimeType': flow.response.headers.get('Content-Type', '')
                },
                'redirectURL': flow.response.headers.get('Location', ''),
                'headersSize': len(str(flow.response.headers)),
                'bodySize': response_body_size,
            },
            'cache': {},
            'timings': timings,
        }
        if strutils.is_mostly_bin(flow.response.content):
            entry['response']['content']['text'] = base64.b64encode(flow.response.content).decode()
            entry['response']['content']['encoding'] = 'base64'
        else:
            entry['response']['content']['text'] = flow.response.get_text(strict=False)
        # adjustment_method = self.adjust_flow(flow)
        # if adjustment_method not in ['strip_content_both', 'strip_content_response']:
        #     if strutils.is_mostly_bin(flow.response.content):
        #         entry['response']['content']['text'] = base64.b64encode(flow.response.content).decode()
        #         entry['response']['content']['encoding'] = 'base64'
        #     else:
        #         entry['response']['content']['text'] = flow.response.get_text(strict=False)
        # else:
        #     entry['response']['content']['_adjustment_method'] = adjustment_method
        # if adjustment_method not in ['strip_content_both', 'strip_content_request']:
        #     entry['request']['_content'] = {}
        #     if strutils.is_mostly_bin(flow.request.content):
        #         entry['request']['_content']['text'] = base64.b64encode(flow.request.content).decode()
        #         entry['request']['_content']['encoding'] = 'base64'
        #     else:
        #         entry['request']['_content']['text'] = flow.request.get_text(strict=False)
        # else:
        #     entry['request']['_content']['adjustment_method'] = adjustment_method
        if flow.request.method in ['POST', 'PUT', 'PATCH']:
            params = [
                {'name': a, 'value': b}
                for a, b in flow.request.urlencoded_form.items(multi=True)
            ]
            entry['request']['postData'] = {
                'mimeType': flow.request.headers.get('Content-Type', ''),
                'text': flow.request.get_text(strict=False),
                'params': params,
            }
        if flow.server_conn.connected():
            entry['serverIPAddress'] = str(flow.server_conn.ip_address[0])
        self.har_data['log']['entries'].append(entry)

    def add_metadata(self, metadata):
        self.har_data['log'].update(metadata)
