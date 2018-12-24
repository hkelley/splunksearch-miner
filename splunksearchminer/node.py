#  Copyright 2016 Palo Alto Networks, Inc
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""
This module implements:
- minemeld.ft.splunk.SavedSearch, the Miner node for Splunk Saved Search results
  feed
"""

import jmespath
import logging
import os
import yaml

from . import json

LOG = logging.getLogger(__name__)

class SavedSearch(json.SimpleJSON):
    """Implements class for miners of JSON feeds over http/https.

    **Config parameters**
        :url: URL of the feed of the Splunk search head (hosting REST API)
        :search_name: name of the Splunk search
        :polling_timeout: timeout of the polling request in seconds.
            Default: 20
        :verify_cert: boolean, if *true* feed HTTPS server certificate is
            verified. Default: *true*
        :username: string, for BasicAuth authentication (*password* required)
        :password: string, for BasicAuth authentication (*username* required)
        :earliest: string, FUTURE
        :latest: string, FUTURE  now
        :extractor: JMESPath expression for extracting the indicators from
            the JSON document. Default: @
        :indicator: the JSON attribute to use as indicator. Default: indicator
        :fields: list of JSON attributes to include in the indicator value.
            If *null* no additional attributes are extracted. Default: *null*
        :prefix: prefix to add to field names. Default: json

    Example:
        Example config in YAML::

            host: splunk.mydomain.com:8089
            extractor: "prefixes[?service=='AMAZON']"
            prefix: aws
            indicator: ip_prefix
            fields:
                - region
                - service

    Args:
        name (str): node name, should be unique inside the graph
        chassis (object): parent chassis instance
        config (dict): node config.
    """

    def __init__(self, name, chassis, config):
        super(SavedSearch, self).__init__(name, chassis, config)

        self.search_name = None

    def configure(self):
        super(SavedSearch, self).configure()

        # self.side_config_path = self.config.get('side_config', None)
        # if self.side_config_path is None:
            # self.side_config_path = os.path.join(
                # os.environ['MM_CONFIG_DIR'],
                # '%s_side_config.yml' % self.name
            # )

        # self._load_side_config()

    def _load_side_config(self):
        super(SavedSearch, self)._load_side_config()

        # try:
            # with open(self.side_config_path, 'r') as f:
                # sconfig = yaml.safe_load(f)

        # except Exception as e:
            # LOG.error('%s - Error loading side config: %s', self.name, str(e))
            # return

        # self.search_name = sconfig.get('search_name', None)
        # if self.search_name is not None:
            # LOG.info('%s - search name set', self.name)


    def _process_item(self, item):
        super(SavedSearch, self)._process_item(item):
        # result = []

        # for htype in ['md5', 'sha256', 'sha1']:
            # value = {self.prefix+'_'+k: v for k, v in item.iteritems()}
            # indicator = value.pop(self.prefix+'_'+htype, None)
            # value['type'] = htype

            # if indicator is not None:
                # result.append([indicator, value])

        # return result

    def _build_iterator(self, now):
        if self.search_name is None:
            LOG.info('%s - search_name not set', self.name)
            raise RuntimeError(
                '%s - search_name not set' % self.name
            )

        if self.compile_error is not None:
            raise RuntimeError(self.compile_error)
        
        rkwargs = dict(
            stream=True,
            verify=self.verify_cert,
            timeout=self.polling_timeout
            auth = (self.username , self.password)
        )

        # Splunk payload
        payload = {
          'search': ("savedsearch \"%s\"" % self.search_name),
          'earliest': self.earliest,
          'latest': self.earliest,
          'output_mode': "json"
        }

        # submit the search,  collect the sid
        url=url_base
        r = requests.post(
          url,
          data=payload,
          **rkwargs
        )
        sid = r.json()["sid"]

        # check the status
        url = '%s/%s?output_mode=json' % (url_base,sid)
        job_data = {}
        elapsed_secs=0
        while (elapsed_secs <= self.polling_timeout and len(job_data) == 0 or job_data["entry"][0]["content"]["dispatchState"] != "DONE"): 
          r = requests.get(
            url,
            **rkwargs
          )
          job_data = json.loads( r.text)
          time.sleep(1) # circuit breaker here
          elapsed_secs += 1
          
        # fetch results
        url = '%s/%s/results?output_mode=json&count=0' % (url_base,sid)
        # print url
        r = requests.get(
          url,
          **rkwargs
        )

        try:
            r.raise_for_status()
        except:
            LOG.debug('%s - exception in request: %s %s',
                      self.name, r.status_code, r.content)
            raise

        result = self.extractor.search(r.json())

        return result

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(SavedSearch, self).hup(source=source)
        

    @staticmethod
    def gc(name, config=None):
        json.SimpleJSON.gc(name, config=config)

        side_config_path = None
        if config is not None:
            side_config_path = config.get('side_config', None)
        if side_config_path is None:
            side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '{}_side_config.yml'.format(name)
            )

        try:
            os.remove(side_config_path)
        except:
            pass

