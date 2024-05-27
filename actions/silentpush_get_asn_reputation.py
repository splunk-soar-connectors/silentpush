# File: silentpush_get_asn_reputation.py
#
# Copyright (c) 2024 Splunk Inc.
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

from urllib.parse import urlencode

import phantom.app as phantom

import silentpush_consts as consts
from actions import BaseAction


class GetAsnReputation(BaseAction):
    """Class to handle get asn reputation action."""

    def execute(self):
        """Execute get asn reputation action.

        Step 1: Validate parameters
        Step 2: Get query params, Optional
        Step 3: Get headers, Optional
        Step 4: Get request body, Optional
        Step 5: Get request url
        Step 6: Invoke API
        Step 7: Handle the response
        """
        self._connector.save_progress(consts.EXECUTION_START_MESSAGE.format('get_asn_reputation'))

        ret_val = self.__validate_params()
        if phantom.is_fail(ret_val):
            return self._action_result.get_status()

        query_params = self.__get_query_params()
        endpoint, method = self.__get_request_url_and_method()

        ret_val, response = self.__make_rest_call(
            url=endpoint,
            method=method,
            param=query_params)

        return self.__handle_response(ret_val, response)

    def __validate_params(self):
        """Validate parameters."""
        ret_val, value = self._connector.validator.validate_integer(
            self._action_result,
            self._param.get('asn'),
            'asn')

        if not ret_val:
            return ret_val

        self._param['asn'] = value

        if 'explain' in self._param:
            ret_val, value = self._connector.validator.validate_boolean(
                self._action_result,
                self._param.get('explain'),
                'explain')

            if not ret_val:
                return ret_val

            self._param['explain'] = int(value)

        if 'limit' in self._param:
            ret_val, value = self._connector.validator.validate_integer(
                self._action_result,
                self._param.get('limit'),
                'limit')

            if not ret_val:
                return ret_val

            self._param['limit'] = value

        return True

    def __get_query_params(self):
        """Get request query parameters."""
        query_params = {
            "explain": "explain",
            "limit": "limit"
        }

        payload = {}
        for key, value in query_params.items():
            if value in self._param:
                payload[key] = self._param[value]

        return payload

    def __get_request_url_and_method(self):
        """Get request endpoint and method."""
        parameters = ["asn"]

        endpoint = consts.GET_ASN_REPUTATION_ENDPOINT
        for parameter in parameters:
            endpoint = endpoint.replace("{{##}}".replace("##", parameter),
                                        str(self._param.get(parameter)))

        return endpoint, 'get'

    def __make_rest_call(self, url, method, headers=None, param=None, body=None):
        """Invoke API."""
        args = {
            "endpoint": url,
            "action_result": self._action_result,
            "method": method.lower(),
            "headers": headers or {}
        }

        if param:
            args['endpoint'] = f'{args["endpoint"]}?{urlencode(param)}'

        args["error_path"] = "response.asn_reputation_history.error"
        return self._connector.util.make_rest_call(**args)

    def __handle_response(self, ret_val, response):
        """Process response received from the third party API."""
        if phantom.is_fail(ret_val):
            return self._action_result.get_status()

        self._action_result.add_data(response)

        summary = {
            "total_asn_reputations": len(response.get("response", {}).get("asn_reputation_history", []))
        }
        self._action_result.update_summary(summary)

        return self._action_result.set_status(
            phantom.APP_SUCCESS,
            consts.ACTION_ASN_REPUTATION_SUCCESS_RESPONSE
        )
