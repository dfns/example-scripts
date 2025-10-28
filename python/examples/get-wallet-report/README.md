# Wallet Report Generator

This project fetches wallet and asset data from the DFNS API and generates a flat CSV report of wallet balances and USD conversions.

## Description

The script performs the following actions:

- Retrieves all wallets using the DFNS `/wallets` endpoint ([doc](https://docs.dfns.co/api-reference/wallets/list-wallets))
- For each wallet, retrieves assets using `/wallets/{wallet_id}/assets` ([doc](https://docs.dfns.co/api-reference/wallets/get-wallet-assets)).
- Writes a CSV file (default name: `wallets.csv`) with one row per asset containing wallet and asset information.

### CSV Output Fields

The generated CSV will contain the following fields:

- **walletId**: `wallet['id']`
- **network**: `wallet['network']`
- **assetKind**: `asset['kind']`
- **assetAddress**: Resolved from one of the asset keys: `metadata`, `assetId`, `contract`, `tokenId`, `coin`, `assetCode`, `mint`, `master` (first present wins). If none present, an empty string is used.
- **assetSymbol**: `asset['symbol']` if present, else an empty string.
- **verifiedAsset**: `asset['verified']` if present, else `False`.
- **balance**: Computed as `int(asset['balance']) / (10 ** asset['decimals'])`
- **conversionUSD**: `asset['quotes']['USD']` if quotes and USD exist, else `0`.

## Usage

1. Set `DFNS_TOKEN` in a `.env` file (rename and fill `.env.example`).
2. Install the requirements: 
    ```bash
    pip install -r requirements.txt
    ```
3. Run the script from the command line: 
    ```bash
    python main.py
    ```
4. The output CSV (default "wallets.csv") will be written in the working directory.

## Token

Which token should you use? 

Easy way: navigate to the Dfns dashboard > Settings > Personal Access Tokens and copy your JWT token. This token is linked to your own user, with the same permission as yours, and is only valid for the duration of your login session.

Finer way: create a [Personal Access Token](https://docs.dfns.co/api-reference/auth/personal-access-tokens) or a [Service Account](https://docs.dfns.co/api-reference/auth/service-accounts) (see the [tutorial here](https://docs.dfns.co/introduction/quickstart/5-start-building-login-and-create-a-wallet-via-api)) based on a [key pair](https://docs.dfns.co/developers/guides/generate-a-key-pair). You can then assign specific permission to restrict access to what is actually needed, in our example: `Wallets:Read` only. 