# DSRAM
Deploy Securely Risk Assessment Model

The purpose of the DSRAM (working title/acronym) is to allow information security professionals to evaluate the financial risk posed by individual vulnerabilities in a simple and, potentially, automated, manner.

There are two primary modules: likelihood and severity. These are the two primary components of calculations allowing for the estimation of the financial value of risk.

The likelihood module is built around the open-source Exploit Prediction Scoring System (EPSS), developed by the Forum of Incident Response and Security Teams (FIRST). The EPSS provides an estimate of the likelihood that a given Common Vulnerability and Exposure (CVE) will be maliciously exploited in the next 30 days. Although not provided by FIRST, the likelihood module also provides the estimated probability of exploitation in the next 365 days as well.

The severity module helps to calculate the loss from the exploitation of a given vulnerability, using the confidentiality, integrity, and availability (CIA) triad. For considerations on what to consider when inputing the various values, please see https://haydock.substack.com/p/the-deploying-securely-risk-assessment.

Finally, an interactive calculator implementing the modules is available via Google Colab: https://colab.research.google.com/drive/1q-04x9zgO9Nh5ap1XmkMJfwm-ahaqkce?usp=sharing. 
