import sys
import os
sys.path.append(os.path.normpath(os.path.join(os.path.dirname(__file__), "../../api")))

from dfnsApi import DfnsAPI
import csv

token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJpc3MiOiJhdXRoLmRmbnMuaW8iLCJhdWQiOiJkZm5zOmF1dGg6dXNlciIsInN1YiI6Im9yLTFtZG9rLTV1dmgwLTllNzluOTlqNWE5azV1MWoiLCJqdGkiOiJ1ai03ZG91bS11NHQ1YS04bjg4NGdvZXFsZzlndW9tIiwiaHR0cHM6Ly9jdXN0b20vdXNlcm5hbWUiOiJqb25hcythZG1pbkBkZm5zLmNvIiwiaHR0cHM6Ly9jdXN0b20vYXBwX21ldGFkYXRhIjp7InVzZXJJZCI6InVzLTRvdmg0LTZhMGg4LTgxb2FoMGZqM3U4bDZkanQiLCJvcmdJZCI6Im9yLTFtZG9rLTV1dmgwLTllNzluOTlqNWE5azV1MWoiLCJ0b2tlbktpbmQiOiJUb2tlbiJ9LCJpYXQiOjE3NjE2NjI2OTksImV4cCI6MTc2MTY4NDI5OX0.qx3Q_Y0LY457XaB0guVpBr4rB_ClQi8xjbXGm9Kkpzi8gDwJFbzl8pnjC3SVxP0SfLLfr-b4Yg8KBN0P2UYeBA"
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
                    'balance': int(asset['balance'])/(10**asset["decimals"]),
                    'conversionUSD': asset['quotes']['USD'] if 'quotes' in asset and 'USD' in asset['quotes'] else 0
                })
                
        print(f"CSV written to: {csv_destination}.")