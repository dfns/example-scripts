import sys
"""
Fetch wallet and asset data from the DFNS API and write a flat CSV report of wallet balances and USD conversions.
    - Retrieves all wallets using the DFNS /wallets endpoint.
    - For each wallet, retrieves assets using /wallets/{wallet_id}/assets.
    - Writes a CSV file (wallets.csv by default) with one row per asset containing wallet and asset information.

CSV output (fieldnames and derived values):
    - walletId: wallet['id']
    - network: wallet['network']
    - assetKind: asset['kind']
    - assetAddress: resolved from one of the asset keys: metadata, assetId, contract, tokenId, coin, assetCode, mint, master (first present wins). If none present, an empty string is used.
    - assetSymbol: asset['symbol'] if present else empty string.
    - verifiedAsset: asset['verified'] if present else False.
    - balance: computed as int(asset['balance']) / (10 ** asset['decimals'])
    - conversionUSD: asset['quotes']['USD'] if quotes and USD exist, else 0.

Usage:
    - Set DFNS_TOKEN in a .env file (rename and fill .env.example).
    - Install the requirements: pip install -r requirements.txt
    - Run the script from the command line: python main.py
    - The output CSV (default "wallets.csv") will be written in the working directory.
"""
import os
sys.path.append(os.path.normpath(os.path.join(os.path.dirname(__file__), "../../api")))

from dfnsApi import DfnsAPI
import csv
from dotenv import load_dotenv
import os
from decimal import Decimal

load_dotenv()

token = os.getenv('DFNS_TOKEN')
csv_destination = "wallets.csv"


def get_all_wallets():
    walletsAPI = DfnsAPI(host="api.dfns.io",
                      endpoint="/wallets",
                      authToken=token)
    
    wallets = list()
    parameters = {'limit': 100}

    while(True):
        res = walletsAPI.get(parameters)
        wallets.extend(res['items'])
        if "nextPageToken" in res:
            parameters['paginationToken'] = res["nextPageToken"]
        else:
            break

    return wallets

def get_wallet_assets(wallet_id):
    walletAssetsAPI = DfnsAPI(host="api.dfns.io",
                              endpoint= f"/wallets/{wallet_id}/assets",
                              authToken=token)
    
    res = walletAssetsAPI.get({'netWorth': 'true'})
    return res['assets']

if __name__ == "__main__": 
    with open(csv_destination, 'w', newline='') as csvfile:
        fieldnames = ['walletId', 'network', 'assetKind', 'assetAddress', 'assetSymbol', 'verifiedAsset', 'balance', 'conversionUSD']
        csvwriter = csv.DictWriter(csvfile, fieldnames=fieldnames)
        csvwriter.writeheader()

        wallets = get_all_wallets()
        print(f"Found {len(wallets)} wallet(s). Fetching balances...")

        for wallet in wallets: 
            assets = get_wallet_assets(wallet['id'])
            for asset in assets: 
                address = ""
                if "metadata" in asset: 
                    address = asset["metadata"]
                elif "assetId" in asset: 
                    address = asset["assetId"]
                elif "contract" in asset: 
                    address = asset["contract"]
                elif "tokenId" in asset: 
                    address = asset["tokenId"]
                elif "coin" in asset: 
                    address = asset["coin"]
                elif "assetCode" in asset: 
                    address = asset["assetCode"]
                elif "mint" in asset: 
                    address = asset["mint"]
                elif "master" in asset: 
                    address = asset["master"]
                else: 
                    address = ""

                csvwriter.writerow({
                    'walletId': wallet['id'],
                    'network': wallet['network'],
                    'assetKind': asset['kind'],
                    'assetAddress': address,
                    'assetSymbol': asset['symbol'] if 'symbol' in asset else '',
                    'verifiedAsset': asset['verified'] if 'verified' in asset else False,
                    'balance': Decimal(int(asset['balance'])) / Decimal(10 ** asset['decimals']),
                    'conversionUSD': asset['quotes']['USD'] if 'quotes' in asset and 'USD' in asset['quotes'] else 0
                })
                
        print(f"CSV written to: {csv_destination}.")