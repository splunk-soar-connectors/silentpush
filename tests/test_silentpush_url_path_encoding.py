# File: test_silentpush_url_path_encoding.py
#
# Copyright (c) 2024-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest
from unittest.mock import Mock

from parameterized import parameterized

from actions.silentpush_density_lookup import DensityLookup
from actions.silentpush_forward_padns_lookup import ForwardPadnsLookup
from actions.silentpush_get_asn_reputation import GetAsnReputation
from actions.silentpush_get_asn_takedown_reputation import GetAsnTakedownReputation
from actions.silentpush_get_asns_seen_for_domain import GetAsnsSeenForDomain
from actions.silentpush_get_domain_certificates import GetDomainCertificates
from actions.silentpush_get_enrichment_data import GetEnrichmentData
from actions.silentpush_get_ipv4_reputation import GetIpv4Reputation
from actions.silentpush_get_job_status import GetJobStatus
from actions.silentpush_get_nameserver_reputation import GetNameserverReputation
from actions.silentpush_get_subnet_reputation import GetSubnetReputation
from actions.silentpush_list_domain_information import ListDomainInformation
from actions.silentpush_list_ip_information import ListIpInformation
from actions.silentpush_reverse_padns_lookup import ReversePadnsLookup


TRAVERSAL_VALUE = "../../api/v2/iocs?source=public&limit=5#fragment"
ENCODED_TRAVERSAL_VALUE = "..%2F..%2Fapi%2Fv2%2Fiocs%3Fsource%3Dpublic%26limit%3D5%23fragment"


class TestSilentpushUrlPathEncoding(unittest.TestCase):
    """Test that action URL path parameters remain path-segment data."""

    @parameterized.expand(
        [
            [
                "density lookup",
                DensityLookup,
                {"qtype": "nssrv", "query": TRAVERSAL_VALUE},
                (),
                f"/api/v1/merge-api/explore/padns/lookup/density/nssrv/{ENCODED_TRAVERSAL_VALUE}",
                "get",
            ],
            [
                "forward padns lookup",
                ForwardPadnsLookup,
                {"qtype": "a", "qname": TRAVERSAL_VALUE},
                (),
                f"/api/v1/merge-api/explore/padns/lookup/query/a/{ENCODED_TRAVERSAL_VALUE}",
                "get",
            ],
            [
                "get asn reputation",
                GetAsnReputation,
                {"asn": TRAVERSAL_VALUE},
                (),
                f"/api/v1/merge-api/explore/ipreputation/history/asn/{ENCODED_TRAVERSAL_VALUE}",
                "get",
            ],
            [
                "get asn takedown reputation",
                GetAsnTakedownReputation,
                {"asn": TRAVERSAL_VALUE},
                (),
                f"/api/v1/merge-api/explore/takedownreputation/history/asn/{ENCODED_TRAVERSAL_VALUE}",
                "get",
            ],
            [
                "get asns seen for domain",
                GetAsnsSeenForDomain,
                {"domain": TRAVERSAL_VALUE},
                (),
                f"/api/v1/merge-api/explore/padns/lookup/domain/asns/{ENCODED_TRAVERSAL_VALUE}",
                "get",
            ],
            [
                "get domain certificates",
                GetDomainCertificates,
                {"domain": TRAVERSAL_VALUE},
                (),
                f"/api/v1/merge-api/explore/domain/certificates/{ENCODED_TRAVERSAL_VALUE}",
                "get",
            ],
            [
                "get enrichment data",
                GetEnrichmentData,
                {"resource": "domain", "value": TRAVERSAL_VALUE},
                (),
                f"/api/v1/merge-api/explore/enrich/domain/{ENCODED_TRAVERSAL_VALUE}",
                "get",
            ],
            [
                "get ipv4 reputation",
                GetIpv4Reputation,
                {"ipv4": TRAVERSAL_VALUE},
                (),
                f"/api/v1/merge-api/explore/ipreputation/history/ipv4/{ENCODED_TRAVERSAL_VALUE}",
                "get",
            ],
            [
                "get job status",
                GetJobStatus,
                {"job_id": TRAVERSAL_VALUE},
                (),
                f"/api/v1/merge-api/explore/job/{ENCODED_TRAVERSAL_VALUE}",
                "get",
            ],
            [
                "get nameserver reputation",
                GetNameserverReputation,
                {"nameserver": TRAVERSAL_VALUE},
                (),
                f"/api/v1/merge-api/explore/nsreputation/history/nameserver/{ENCODED_TRAVERSAL_VALUE}",
                "get",
            ],
            [
                "get subnet reputation",
                GetSubnetReputation,
                {"subnet": TRAVERSAL_VALUE},
                (),
                f"/api/v1/merge-api/explore/ipreputation/history/subnet/{ENCODED_TRAVERSAL_VALUE}",
                "get",
            ],
            [
                "list domain information live WHOIS",
                ListDomainInformation,
                {},
                ("live_whois", TRAVERSAL_VALUE),
                f"/api/v1/merge-api/explore/domain/whoislive/{ENCODED_TRAVERSAL_VALUE}",
                "get",
            ],
            [
                "list ip information resource",
                ListIpInformation,
                {},
                (TRAVERSAL_VALUE,),
                f"/api/v1/merge-api/explore/bulk/ip2asn/{ENCODED_TRAVERSAL_VALUE}",
                "post",
            ],
            [
                "reverse padns lookup",
                ReversePadnsLookup,
                {"qtype": "a", "qname": TRAVERSAL_VALUE},
                (),
                f"/api/v1/merge-api/explore/padns/lookup/answer/a/{ENCODED_TRAVERSAL_VALUE}",
                "get",
            ],
        ]
    )
    def test_url_path_parameters_are_encoded(self, _, action_class, parameters, method_args, expected_endpoint, expected_method):
        """Test that traversal syntax cannot change the requested endpoint."""
        action = action_class(Mock(), parameters)
        get_request_url_and_method = getattr(action, f"_{action_class.__name__}__get_request_url_and_method")

        endpoint, method = get_request_url_and_method(*method_args)

        self.assertEqual(endpoint, expected_endpoint)
        self.assertEqual(method, expected_method)
