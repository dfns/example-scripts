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
