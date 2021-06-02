# splunksearch-miner
MineMeld miner for Splunk searches implemented as an extension

## How it works
This miner periodically executes a Splunk saved search via REST and returns a columns as indicators.

## Installation

Install this extension directly from the git repo using your MineMeld server's System | Extensions menu.

## Configuration

I should re-work this so that the username and password go in the private (node-level) storage.  Someday ....
- If your saved search is not in the default search app then use a URL like this:
"https://xxx.splunkcloud.com:8089/servicesNS/nobody/<APP_NAME>/search/jobs/"
- User role permissions will suffice
- In the prototype configuration,  use double-quotes around the search name, password, or anywhere else that has YAML special characters.
