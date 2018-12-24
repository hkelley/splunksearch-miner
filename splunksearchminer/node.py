import logging
import jmespath
import json
import requests
import time

from minemeld.ft.json import SimpleJSON

LOG = logging.getLogger(__name__)

class SavedSearch(SimpleJSON):

    def __init__(self, name, chassis, config):
        super(SavedSearch, self).__init__(name, chassis, config)

        self.search_name = None

    def configure(self):
        super(SavedSearch, self).configure()
 
        self.earliest = self.config.get('earliest', "-2d")
        self.latest = self.config.get('latest', "now")
        self.search_name = self.config.get('search_name', None)
        if self.search_name is None:
            raise ValueError('%s - search name is required' % self.name)


    def _build_iterator(self, now):

        if self.compile_error is not None:
            raise RuntimeError(self.compile_error)
        
        url_base = self.url
        
        # Request options
        rkwargs = dict(
            stream=True,
            verify=self.verify_cert,
            timeout=self.polling_timeout,
            auth = (self.username , self.password)
        )
        for i in rkwargs:
          LOG.debug('%s - request setting: %s = %s' ,
            self.name,i,rkwargs[i])

        LOG.debug('%s - HACK: %s' ,        self.name,("savedsearch \"%s\"" % self.search_name))
        # Splunk payload
        payload = {
          'search': ("savedsearch \"%s\"" % self.search_name),
          'earliest': self.earliest,
          'latest': self.latest,
          'output_mode': "json"
        }
        for i in payload:
          LOG.debug('%s - POST payload value: %s = %s' ,
            self.name,i,payload[i])

        # submit the search,  collect the sid
        url=url_base
        r = requests.post(
          url,
          data=payload,
          **rkwargs
        )
        LOG.debug('%s - Splunk sid received: %s ' ,
          self.name, r.text)
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
          LOG.debug('%s - Splunk sid %s status: %s' , 
                    self.name, sid,r.text)
          job_data = r.json()
          time.sleep(1)
          elapsed_secs += 1   # circuit breaker in while loop
          
        # fetch results
        url = '%s/%s/results?output_mode=json&count=0' % (url_base,sid)
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

    def _process_item(self, item):
        item = super(SavedSearch, self)._process_item(item)
        return item
