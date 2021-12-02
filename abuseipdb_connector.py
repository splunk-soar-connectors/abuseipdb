# File: abuseipdb_connector.py
#
# Copyright (c) 2017-2021 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

import requests
import json
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class AbuseipdbConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(AbuseipdbConnector, self).__init__()

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                                                                      error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, response, action_result):

        # Try a json parse
        try:
            resp_json = response.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                  response.status_code, response.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, response, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': response.status_code})
            action_result.add_debug_data({'r_text': response.text})
            action_result.add_debug_data({'r_headers': response.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in response.headers.get('Content-Type', ''):
            return self._process_html_response(response, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not response.text:
            return self._process_empty_response(response, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                  response.status_code, response.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, json_data=None, method="post"):

        # Build headers for v2 API Requests
        if not headers:
            headers = dict()
        headers['key'] = self._api_key
        headers['accept'] = "application/json"

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = "{}{}".format(self._base_url, endpoint)

        try:
            r = request_func(
                url,
                json=json_data,
                headers=headers,
                params=params)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        # To validate the API key during a test connectivity action, it is necessary to check for
        # HTTP code 429 since we need to Report (post_ip) 127.0.0.1 causing said error if test connectivity was run
        # within an interval of 15 min of testing again
        if self.get_action_identifier() == 'test_connectivity' and r.status_code == 429:
            return RetVal(action_result.set_status(phantom.APP_SUCCESS, ''), None)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to AbuseIPDB")

        # build body data for POST request
        ip = "127.0.0.1"
        categories = "4"
        comment = "Test Connectivity"
        data = {"ip": ip, "categories": categories, "comment": comment}

        # make rest call
        ret_val, response = self._make_rest_call('/report', action_result, json_data=data, params=None, headers=None)

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_ip(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param['ip']
        max_age_in_days = param['days']
        verbose = 'yes'
        params = {"ipAddress": ip, "maxAgeInDays": max_age_in_days, "verbose": verbose}

        # make rest call
        # The response is a list of all the reports that we got back from checking the IP
        ret_val, reports = self._make_rest_call('/check', action_result, json_data=None, params=params, headers=None, method="get")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the reports into the data section
        action_result.add_data(reports)

        reports_list = []
        if reports:
            data = reports.get('data')
            if data:
                reports_list = data.get('reports')

        summary = action_result.update_summary({})
        summary['reports_found'] = len(reports_list)

        message = "IP lookup complete. Reports found: {}".format(
            summary['reports_found'])

        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_report_ip(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param['ip']
        categories = param['category_ids']
        categories = ','.join(list(filter(None, categories.split(','))))
        comment = param.get('comment', '')

        data = {"ip": ip, "categories": categories, "comment": comment}
        # make rest call
        ret_val, response = self._make_rest_call('/report', action_result, json_data=data, params=None, headers=None)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        summary = action_result.update_summary({})
        list_categories = categories.strip().replace(' ', '').split(',')
        summary['categories_filed'] = len(list_categories)
        summary['comment_length'] = len(comment)

        message = "IP reported. Number of categories filed: {}, Comment length: {}".format(
            summary['categories_filed'],
            summary['comment_length'])

        return action_result.set_status(phantom.APP_SUCCESS, message)

    def handle_action(self, param):

        self.debug_print("action_id", self.get_action_identifier())

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'lookup_ip': self._handle_lookup_ip,
            'report_ip': self._handle_report_ip
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in list(action_mapping.keys()):
            action_function = action_mapping[action]
            action_execution_status = action_function(param)

        return action_execution_status

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # API v2
        self._base_url = "https://api.abuseipdb.com/api/v2"

        # get the asset config
        config = self.get_config()

        self._api_key = config['api_key']

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print("Accessing the Login page")
            r = requests.get(BaseConnector._get_phantom_base_url() + "login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = BaseConnector._get_phantom_base_url() + "login"

            print("Logging into Platform to get the session id")
            r2 = requests.post(BaseConnector._get_phantom_base_url() + "login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = AbuseipdbConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
