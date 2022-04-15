def get_all_epss():
  # The Exploit Prediction Scoring System (EPSS) is an open source model provided by the non-profit
  # Forum of Incident Response and Security Teams (FIRST).
  # At a high level, the score refers to the probability (0-1 scale) that a Common Vulnerability and Exposure (CVE)
  # will be exploited by a malicious actor in the next 30 days.
  # Please see https://www.first.org/epss/model for additional details on how to interpet the results.
  # See this article for a high-level analysis: https://haydock.substack.com/p/deep-dive-into-the-epss.

  # Pandas is a very useful Python library for data manipulation, cleaning, and analysis.
  import pandas as pd

  # get EPSS data
  df_epss = pd.read_csv('https://epss.cyentia.com/epss_scores-current.csv.gz', compression='gzip', encoding='utf8')

  # Cleaning up the epss data
  df_epss = df_epss.rename(columns={list(df_epss)[0]: "epss_30_day",\
                                    list(df_epss)[1]: "percentile"})
  df_epss = df_epss.drop(index='cve')
  df_epss['epss_30_day'] = df_epss['epss_30_day'].astype(float)
  df_epss['percentile'] = df_epss['percentile'].astype(float)
  
  return df_epss

def get_epss_30_from_cve_id(cve_id):
  import numpy as np
  try:
    result = df_epss.loc[cve_id]['epss_30_day']
  except:
    result = np.nan
  return result

def get_epss_30_percentile_from_cve_id(cve_id):
  import numpy as np
  try:
    result = df_epss.loc[cve_id]['percentile']
  except:
    result = np.nan
  return result * 100

def get_nvd_data(list_of_years):
  from urllib.request import urlopen
  from io import BytesIO
  from zipfile import ZipFile
  import pandas as pd

  counter = 0
  df = []
  
  for year in list_of_years:
    url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-'+str(year)+'.json.zip'
    extract_target = 'nvdcve-1.1-'+str(year)+'.json'
    # Extracting zip file
    z = urlopen(url)
    stage_1 = z.read()
    stage_2 = (BytesIO(stage_1))
    stage_3 = ZipFile(stage_2)
    stage_4 = stage_3.extract(extract_target)
    yearly_data = pd.read_json(stage_4)
    if counter == 0:
        df = yearly_data
    else:
        df = df.append(yearly_data)
    counter +=1

  # Flatenning CVE_Items
  CVE_Items = pd.json_normalize(df["CVE_Items"])

  # Concatenating and cleaning up the data frame by dropping the original index as well as the nested JSON column
  df = pd.concat([df.reset_index(), CVE_Items], axis=1)
  df_cves = df.drop(["index", "CVE_Items"], axis=1)
  
  from datetime import datetime, timedelta
  import pytz
  df_cves['publishedDate'] = pd.to_datetime(df_cves['publishedDate'])
  now = datetime.utcnow().replace(tzinfo=pytz.utc)
  df_cves['cve_age'] = now - df_cves['publishedDate']

  # Creating function to convert timedelta into float
  def timedelta_to_second(timedelta):
    return timedelta.total_seconds() / 86400 # number of seconds in a day

  # Converting timedelta to days (float)
  df_cves['cve_age'] = df_cves['cve_age'].apply(timedelta_to_second)
  
  # setting index to CVE ID
  df_cves = df_cves.set_index(['cve.CVE_data_meta.ID'])
  
  return df_cves

def epss_365_day_from_epss_30_day(cve_age, epss_30_day):
  # This is VERY ROUGH, but essentially I developed an "exploitation curve" function to predict the likelihood of exploitation over time of a given vulnerability
  # According to Mandiant (https://www.mandiant.com/resources/time-between-disclosure-patch-release-and-vulnerability-exploitation), of all known vulnerabilities that are exploited,
  # 1/3 are exploited in the first week of identification, 
  # 1/3 are exploited in the subsequent month (but excluding the first week),
  # and the remaining 1/3 are exploited after one month of identification.
  # This roughly corresponds to a function for risk_of_exploitation = .05 ^ (.025 * CVE age)
  
  def exploitation_curve(cve_age):
      exploitation_curve = 0.05**(0.025 * float(cve_age))
      return exploitation_curve
  
  months = [1,2,3,4,5,6,7,8,9,10,11]
  epss_365_day = epss_30_day # setting these equal before beginning the for loop
  
  for month in months:
    days = cve_age + (month * (365.25/12)) # This is the age of the cve (today) plus the number of days in a year divided by the number of months in a year
    ### Using this formula, and the CVE's age, I will predict the EPSS for each subsequent month (after the 30 day period)
    marginal_epss = (exploitation_curve(days) * epss_30_day)
    epss_365_day = epss_365_day + marginal_epss
  
  return epss_365_day

def non_cve_exploitability_score(user_interaction, privileges_required, attack_vector):
  if user_interaction:
    if privileges_required:
      if attack_vector == "adjacent_network":
        exploitability_score = float(0.009125)
      if attack_vector == "physical":
        exploitability_score = float(0.009484)
      if attack_vector == "network":
        exploitability_score = float(0.011233)
      if attack_vector == "local":
        exploitability_score = float(0.011900)
    if not privileges_required:
      if attack_vector == "adjacent_network":
        exploitability_score = float(0.020369)
      if attack_vector == "physical":
        exploitability_score = float(0.009634)
      if attack_vector == "network":
        exploitability_score = float(0.028147)
      if attack_vector == "local":
        exploitability_score = float(0.020971)
  if not user_interaction:
    if privileges_required:
      if attack_vector == "adjacent_network":
        exploitability_score = float(0.017078)
      if attack_vector == "physical":
        exploitability_score = float(0.012106)
      if attack_vector == "network":
        exploitability_score = float(0.020974)
      if attack_vector == "local":
        exploitability_score = float(0.011861)
    if not privileges_required:
      if attack_vector == "adjacent_network":
        exploitability_score = float(0.029069)
      if attack_vector == "physical":
        exploitability_score = float(0.010787)
      if attack_vector == "network":
        exploitability_score = float(0.028147)
      if attack_vector == "local":
        exploitability_score = float(0.011424)  
  
