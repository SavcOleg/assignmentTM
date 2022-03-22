import requests
import time
import json
import pandas as pd
import base64
import datetime
import argparse

"""
Assignment number 1 

csv_data_base >>> path to csv database
"""


def setup() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument('--csv_data_base', required=True,
                        metavar='PATH', help='csv_data_base', dest="csv_data_base")
    return parser.parse_args()


def get_data_from_API(url: str) -> None:
    """
    parse data from  api
    :param url:
    :return:
    """
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "Accept": "application/json",
        "x-apikey": "3b983bc9df0987532e9bb14fd266ff044e5ea4c235dadf7b0f9a87dd671e60b1"}
    response = requests.request("GET", url, headers=headers)
    json_response = json.loads(response.text)
    return json_response


def get_data_vote_from_API(url: str) -> None:
    """
    Parse Vote API
    :param url: url hash for build link
    :return: text
    """
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}/votes"
    headers = {
        "Accept": "application/json",
        "x-apikey": "3b983bc9df0987532e9bb14fd266ff044e5ea4c235dadf7b0f9a87dd671e60b1"}
    response = requests.request("GET", url, headers=headers)
    json_response = json.loads(response.text)
    return json_response


def only_last_30_min(dataframe: pd.DataFrame) -> pd.DataFrame:
    dataframe["last_query"] = dataframe["last_query"].fillna(datetime.datetime.utcnow())
    dataframe['last_query'] = pd.to_datetime(dataframe['last_query'])
    created_time = datetime.datetime.utcnow() - datetime.timedelta(minutes=30)
    dataframe = dataframe[
        (dataframe['last_query'] < created_time)]
    return dataframe


if __name__ == '__main__':
    args = setup()

    domain_CSV = pd.read_csv(args.csv_data_base)
    save_results = only_last_30_min(domain_CSV.copy())
    Urls = save_results['Domain'].tolist()
    print(save_results)

    for i_url in Urls:
        print(i_url)
        print(get_data_from_API(i_url))
        if get_data_from_API(i_url)['data']['attributes']['last_analysis_results']['Phishing Database']['result'] \
                == 'clean':
            if get_data_from_API(i_url)['data']['attributes']['last_analysis_results']['Malwared']['result'] == 'clean':
                save_results.loc[save_results.Domain == i_url, "Sites_risk"] = 'safe'
            else:
                save_results.loc[save_results.Domain == i_url, "Sites_risk"] = 'risk'
        else:
            save_results.loc[save_results.Domain == i_url, "Sites_risk"] = 'risk'
        save_results.loc[save_results.Domain == i_url, "Total_voting"] = get_data_vote_from_API(i_url)['meta']['count']
        save_results.loc[save_results.Domain == i_url, "Category_by_Forcepoint ThreatSeeker"] = \
            get_data_from_API(i_url)['data']['attributes']['categories']['Forcepoint ThreatSeeker']
        save_results.loc[save_results.Domain == i_url, "last_query"] = pd.Timestamp.now()
        time.sleep(25)
        save_results.to_csv(args.csv_data_base, index=False)
