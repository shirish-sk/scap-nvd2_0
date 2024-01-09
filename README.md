# scap-nvd2_0
Repo for SCAP based NVD 2.0 API Data Feed ingestion

Navigating the Transition - Leveraging the NVD 2.0 API for SCAP-Based Automated Vulnerability Management

In response to the recent changes in accessing critical vulnerability information(via NIST based sources), adapting to the SCAP based NVD 2.0 APIs over the traditional workflows like legacy data feeds(RSS) and web scraping, could act as a resilient solution to navigate the automated vulnerability management strategy across infrastructure-agnostic environments. 


Thinking of ever-evolving threat landscape? Why not  embrace this integration alongside SCAP-based vulnerability management?



**=**=****=**=****=**=****=**=****=**=****=***
**=**=****=**=**RUN SEQUENCE**=**=****=**=****
**=**=****=**=****=**=****=**=****=**=****=***
1. Run the SCAPService Endpoint and OAuth2 Authenticator (Sample - sampleSCAPServiceEndpoint.py) 
2. Initiate the CVE Feed from the NVD 2.0 source (Sample - cvefeedInterceptor.py)
3. Ingest and process the Raw JSON stream to extract the CVE details (example: CVE ID, Base Severity, Description)
4. Distribute the releavant data stream within the organizational CyberSec realms
 
