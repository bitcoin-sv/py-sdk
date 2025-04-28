# Step-by-Step BSV Tutorial: Sending BSV and NFTs

This beginner-friendly guide will walk you through sending BSV (Bitcoin SV) and creating NFTs using the BSV Python SDK. We'll take it step-by-step so you can learn at your own pace. 

- [Prerequisites](#prerequisites)
- [Setting Up Your Environment](#setting-up-your-environment)
- [Creating Keys and Addresses](#creating-keys-and-addresses)
- [Fetching Transaction Data](#fetching-transaction-data)
- [Sending BSV](#sending-bsv)
- [Creating and Sending NFTs](#creating-and-sending-nfts)
- [Understanding Transaction Inputs and Outputs](#understanding-transaction-inputs-and-outputs)
- [Key Terms](#key-terms)

## Prerequisites

- Python 3.6+ installed
- Basic command line knowledge
- A small amount of BSV for testing

## Setting Up Your Environment

Let's start by creating a project folder and setting up a virtual environment.

### Step 1: Create a project folder

Open your terminal (Command Prompt or PowerShell on Windows) and run:

```bash
mkdir bsv_tutorial
cd bsv_tutorial

```

### Step 2: Create a virtual environment

This keeps your project dependencies separate from other Python projects:

```bash
python -m venv venv

```

### Step 3: Activate the virtual environment

**On macOS/Linux:**

```bash
source venv/bin/activate

```

**On Windows:**

```bash
venv\Scripts\activate

```

Your command prompt should now show `(venv)` at the beginning, indicating the virtual environment is active.

### Step 4: Install required packages

```bash
pip install bsv-sdk

```

This might take a moment to complete. Once done, you'll have all the basic libraries needed for this tutorial.

## Creating Keys and Addresses

Before we can send or receive BSV, we need to create some cryptographic keys and addresses.

### Step 1: Create a Python file for key generation

Create a new file named `generate_address.py` in your project folder using any text editor.

### Step 2: Add code to import the required library

```python
from bsv import PrivateKey

```

### Step 3: Add code to generate a private key for the sender

```python
# Generate sender address (Address A)
priv_key_a = PrivateKey()
wif_a = priv_key_a.wif()  # Wallet Import Format
address_a = priv_key_a.address()

```

### Step 4: Add code to generate a private key for the receiver

```python
# Generate receiver address (Address B)
priv_key_b = PrivateKey()
wif_b = priv_key_b.wif()
address_b = priv_key_b.address()

```

### Step 5: Add code to display and save the keys and addresses

```python
# Print out the keys and addresses
print("\n===== SENDER INFORMATION =====")
print(f"Private Key: {wif_a}")
print(f"Address: {address_a}")

print("\n===== RECEIVER INFORMATION =====")
print(f"Private Key: {wif_b}")
print(f"Address: {address_b}")

# Save data to file for easy reference
with open("wallet_info.txt", "w") as f:
    f.write(f"Sender Private Key: {wif_a}\n")
    f.write(f"Sender Address: {address_a}\n\n")
    f.write(f"Receiver Private Key: {wif_b}\n")
    f.write(f"Receiver Address: {address_b}\n")
print("\nThis information has been saved to wallet_info.txt")

```

### Step 6: Add the main function to run the code

```python
def main():
    # The code from Steps 3-5 goes here

if __name__ == "__main__":
    main()

```

### Step 7: Run your script

Save the file and run it from your terminal:

```bash
python generate_address.py

```

You should see information about your newly generated keys and addresses. The same information is also saved in a file called `wallet_info.txt` for future reference.

> 🔒 Important: Keep your private keys secure! Anyone with access to a private key can spend the BSV associated with it.
> 

### Step 8: Fund your sender address

In order to send BSV or create NFTs, you need to have some BSV in your sender address. Send a small amount of BSV to your sender address (Address A) using a wallet like HandCash or BetterWallet.

## Fetching Transaction Data

To send BSV, we need information about previous transactions that sent BSV to our address. We can get this information in two ways:

### Manually fetching the raw transaction  hex from the WhatsOnChain Website

### Step 1: Visit WhatsOnChain

Go to [WhatsOnChain](https://whatsonchain.com/) in your web browser.

### Step 2: Search for your address

Enter your sender address (Address A) in the search bar and press Enter.
![CleanShot 2025-04-08 at 01.07.06@2x.png](images/CleanShot%202025-04-08%20at%2001.07.06%402x.png)

### Step 3: Find a transaction

Look for a transaction that sent BSV to your address. Click on the transaction ID to view its details.
![CleanShot 2025-04-08 at 01.07.39@2x.png](images/CleanShot%202025-04-08%20at%2001.07.39%402x.png)

### Step 4: Get the raw transaction hex

Click on the "Raw Tx" button to download the raw transaction hex.
![CleanShot 2025-04-08 at 01.08.48@2x.png](images/CleanShot%202025-04-08%20at%2001.08.48%402x.png)

### Step 5: Copy the hex string

Select and copy the entire hex string. You'll need this for sending BSV.

## Sending BSV

Now that we have our keys, addresses, and transaction data, we can send BSV from one address to another. Let's go through this process step by step.

### Step 1: Create a new file named `send_bsv.py`

Open your text editor and create a new file. Save it as `send_bsv.py` in your project folder.

### Step 2: Add code to import the required libraries

First, we need to import the necessary libraries. Type the following code at the top of your file:

```python
import asyncio
from bsv import (
    PrivateKey, P2PKH, Transaction, TransactionInput, TransactionOutput
)
```

These imports provide all the tools we need to create and broadcast a BSV transaction.

### Step 3: Set up the transaction variables

Now let's set up the variables for our transaction. Add the following code to your file:

```python
# Replace with your source transaction hex from WhatsOnChain
SOURCE_TX_HEX='source transaction raw hex'

async def create_and_broadcast_transaction():
    # Create a private key object from your WIF you created previously
    # Make sure to specify the private key that has BSV
    priv_key = PrivateKey('private key')  # Replace with your private key

    # Create a transaction object from the hex
    source_tx = Transaction.from_hex(SOURCE_TX_HEX)

```

In the code above:

- Replace `source transaction raw hex` with the raw transaction hex you copied from WhatsOnChain
- Replace `private key` with your private key in WIF format

### Step 4: Create the transaction input

Next, we'll create the transaction input, which specifies which UTXO (unspent transaction output) we want to spend. Add this code:

```python
    # Create the transaction input
    tx_input = TransactionInput(
        source_transaction=source_tx,
        source_txid=source_tx.txid(),
        source_output_index=0,  # Replace with the correct output index
        unlocking_script_template=P2PKH().unlock(priv_key),
    )

```

In the code above:

- Replace `0` with the correct output index. This is the position of the output in the transaction that belongs to your address. For the first output, use 0; for the second, use 1; and so on. For example, you might see something simple like this with one input and two outputs. The transaction you are making now in the end will look something like this. Where 500 is the amount of satoshi’s to send and the change gets sent to your change address.

- ![CleanShot 2025-04-10 at 22.10.16@2x.png](images/CleanShot%202025-04-10%20at%2022.10.16%402x.png) 
  
    In other cases, you might see more complicated ones like this, but to figure out which is the correct output you just need to find your address you sent BSV to from your wallet in the outputs. 
![CleanShot 2025-04-10 at 22.10.54@2x.png](images/CleanShot%202025-04-10%20at%2022.10.54%402x.png)
 

### Step 5: Create the transaction outputs

Now we'll create the transaction outputs - one for the recipient and one for change. Add this code:

```python
    # Create the output for the recipient
    tx_output = TransactionOutput(
        locking_script=P2PKH().lock('recipient address'),  # Replace with recipient address
        satoshis = 2,  # Replace with amount to send
        change=False
    )

    # Create the output for change back to you
    tx_output_change = TransactionOutput(
        locking_script=P2PKH().lock('change address'),  # Replace with your address for change
        change=True
    )

```

In the code above:

- Replace `recipient address` with the recipient's BSV address
- Replace `2` with the amount of satoshis you want to send (remember: 1 BSV = 100,000,000 satoshis)
- Replace `change address` with your own BSV address to receive change

### Step 6: Build, sign, and broadcast the transaction

Now we'll build the transaction, calculate the fee, sign it, and broadcast it to the network. Add this code:

```python
    # Create the transaction with inputs and outputs
    tx = Transaction([tx_input], [tx_output, tx_output_change])

    # Calculate the fee and update the change output
    tx.fee()

    # Sign the transaction
    tx.sign()

    # Broadcast the transaction to the network
    response = await tx.broadcast()
    print(f"Broadcast Response: {response}")

    # Print the transaction ID and raw hex
    print(f"Transaction ID: {tx.txid()}")
    print(f"Raw hex: {tx.hex()}")

```

### Step 7: Add the main function to run the code

Finally, add the code to run our function:

```python
if __name__ == "__main__":
    asyncio.run(create_and_broadcast_transaction())

```

### Step 8: Save and run the script

Make sure to save your file, then run it from your terminal:

```bash
python send_bsv.py

```

If everything is set up correctly, the script will create and broadcast a transaction that sends BSV from your address to the recipient address.

### Step 9: Verify the transaction

After broadcasting, the script will display the transaction ID. You can verify that your transaction was successful by checking it on WhatsOnChain. Visit:

```
https://whatsonchain.com/tx/{transaction_id}

```

Replace `{transaction_id}` with the actual transaction ID displayed by the script.

> 💡 Tip: Before sending a transaction with real BSV, you can check its content with the WhatsOnChain Decoder to make sure everything is set up correctly. Understanding what comprises a transaction (inputs and outputs) will help you learn how the BSV blockchain works.
> 

## Creating and Sending NFTs

Now let's learn how to create and send NFTs (Non-Fungible Tokens) on the BSV blockchain. We'll be using the 1Sat Ordinals protocol, which allows you to attach data to a satoshi (the smallest unit of BSV) to create an NFT.

> ⚠️ Important Note: After sending BSV in the previous section, you will need to fetch a new transaction hex for creating an NFT. This is because each transaction can only be used once - after you've spent a UTXO (Unspent Transaction Output), you need to find a new unspent transaction to use as input.
> 

### Step 1: Install additional required packages

First, we need to install the package that helps us create 1Sat Ordinals NFTs. Open your terminal and run:

```bash
pip install yenpoint_1satordinals

```

This package provides functions to help create the special transaction outputs needed for 1Sat Ordinals.

### Step 2: Prepare your NFT file

Create a folder for your NFT data:

```bash
mkdir sample_data

```

Now place an image or other data file that you want to turn into an NFT in this folder. For example, if you have a JPEG image, copy it to the sample_data folder.

### Step 3: Create a new file named `send_nft.py`

Open your text editor and create a new file. Save it as `send_nft.py` in your project folder.

### Step 4: Add code to import the required libraries

Type the following code at the top of your file to import all the necessary libraries:

```python
import nest_asyncio
import asyncio
from pathlib import Path

from yenpoint_1satordinals import add_1sat_outputs
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput
from bsv.transaction import Transaction
from bsv import PrivateKey
from bsv.script import P2PKH
from bsv import SatoshisPerKilobyte

```

These imports provide all the tools we need to create and broadcast an NFT transaction.

### Step 5: Set up the nest_asyncio and main function

Next, add the code to set up nest_asyncio (which allows asyncio to work in various environments) and create the main function:

```python
# Apply nest_asyncio to allow asyncio to work in interactive environments
nest_asyncio.apply()

async def main():
    try:
        # We'll add more code here in the next steps
        pass
    except Exception as e:
        print(f"Error occurred: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())

```

### Step 6: Configure the NFT data and outputs

Inside the main function (replacing the `pass` statement), add the code to specify your NFT file and recipient:

```python
        # Specify the path to your NFT file
        data_path = Path("sample_data/my_image.jpg")  # Replace with your image path

        # Create the outputs for the NFT transaction
        outputs = add_1sat_outputs(
            ordinal_address="1JamH87AESzYNZkpAKsHWY7CUPgErDGdNS",  # Replace with NFT recipient address
            data=data_path,
            change_address="17wxeSxYyUrtygrsNiK5tGTcoxksBRMU3Y"  # Replace with your change address
        )

```

Make sure to:

- Replace `"sample_data/my_image.jpg"` with the path to your actual NFT file
- Replace `"1JamH87AESzYNZkpAKsHWY7CUPgErDGdNS"` with the address that should receive the NFT
- Replace `"17wxeSxYyUrtygrsNiK5tGTcoxksBRMU3Y"` with your own address to receive change

### Step 7: Set up the transaction input

Continue adding code inside the main function to set up the input for your transaction:

```python
        # Specify which output from the previous transaction to use
        previous_tx_vout = 2  # Replace with correct output index

        # Replace this with your raw transaction hex from WhatsOnChain
        previous_tx_rawtx=""  # Paste your hex string here
        previous_tx = Transaction.from_hex(previous_tx_rawtx)

        # Set up your private key
        sender_private_key = PrivateKey("L1X1sP2CvKMKREphv66oN----------nyH35JxFur5LQHeJWDoW")  # Replace with your private key

        # Create the transaction input
        tx_input = TransactionInput(
            source_transaction=previous_tx,
            source_txid=previous_tx.txid(),
            source_output_index=previous_tx_vout,
            unlocking_script_template=P2PKH().unlock(sender_private_key)
        )

```

Make sure to:

- Replace `2` with the correct output index that contains your funds
- Add your raw transaction hex to `previous_tx_rawtx=""` (paste between the quotes)
- Replace the private key with your own private key in WIF format

### Step 8: Build, sign, and broadcast the NFT transaction

Finally, add the code to build, sign, and broadcast the transaction:

```python
        # Create the transaction with the input and NFT outputs
        tx = Transaction([tx_input], outputs)

        # Calculate the fee and update the change output
        tx.fee()

        # Sign the transaction
        tx.sign()

        # Get the transaction ID and raw hex
        thetxid = tx.txid()
        txhex = tx.hex()
        print(f"HEX:{txhex}")

        # Broadcast the transaction to the network
        result = await tx.broadcast()
        print(f"Txid:{result.txid}")
        print(f"Status:{result.status}")

```

### Step 9: Save and run the script

Make sure to save your file with all the code from steps 4-8, then run it from your terminal:

```bash
python send_nft.py

```

If everything is set up correctly, the script will create and broadcast a transaction that creates an NFT and sends it to the specified address.

### Step 10: Verify the NFT transaction

After broadcasting, the script will display the transaction ID. You can verify that your NFT transaction was successful by checking it on WhatsOnChain. Visit:

```
https://whatsonchain.com/tx/{transaction_id}

```

Replace `{transaction_id}` with the actual transaction ID displayed by the script.

You can also view your NFT on special 1Sat Ordinals explorers like:

```
https://ordinals.gorillapool.io/content/{transaction_id}_0

```

Replace `{transaction_id}` with your actual transaction ID.

## Understanding Transaction Inputs and Outputs

Throughout this tutorial, you've been working with transaction inputs and outputs. Let's clarify what these are and how they function in the Bitcoin system:

### Transaction Inputs

- **What are inputs?** Inputs are references to previous transaction outputs that you want to spend. They point to where your BSV came from.
- **Components:**
    - **Source TXID:** The transaction ID of the previous transaction that contains the output you're spending
    - **Output Index:** Which output from that previous transaction you're spending (0 for first, 1 for second, etc.)
    - **Unlocking Script:** The script that proves you have the right to spend this output (typically a signature from your private key)
- **Think of inputs as:** Money coming into your transaction - like cash you're taking out of your wallet to spend.

### Transaction Outputs

- **What are outputs?** Outputs define where your BSV goes after the transaction. They create new "unspent outputs" (UTXOs) that can be used as inputs in future transactions.
- **Components:**
    - **Amount:** How many satoshis this output contains
    - **Locking Script:** The conditions required to spend this output in the future (typically requiring a signature from the recipient's private key)
- **Think of outputs as:** Money going out of your transaction - some to the recipient and typically some back to yourself as change.

### Key Insight

In Bitcoin's UTXO model, you don't actually have a "balance" in the traditional sense. Instead, you have a collection of unspent outputs (UTXOs) from previous transactions that you can spend. When you create a transaction:

1. You consume one or more UTXOs as inputs
2. You create new UTXOs as outputs
3. The sum of input values must be greater than or equal to the sum of output values
4. The difference is the transaction fee that goes to miners

This is why you always need a change output when you don't want to spend the entire value of your input - the system works like physical cash where you need to make change.

## Key Terms

- **Private Key**: A secret number used to sign transactions and prove ownership of Bitcoin addresses.
- **WIF (Wallet Import Format)**: A user-friendly format for encoding private keys.
- **Address**: A string of characters used to receive BSV, derived from a public key.
- **Raw Transaction Hex**: A hexadecimal representation of a transaction.
- **Satoshi**: The smallest unit of BSV (1 BSV = 100,000,000 satoshis).
- **NFT (Non-Fungible Token)**: A unique digital asset representing ownership of a specific item or content.
- **WhatsOnChain**: A block explorer for viewing BSV blockchain data and transactions.
- **UTXO (Unspent Transaction Output)**: An output from a previous transaction that can be used as an input for a new transaction.
- **API (Application Programming Interface)**: A set of rules that allows different software applications to communicate with each other.
- **Transaction ID (TXID)**: A unique identifier for a transaction on the blockchain.
- **Output Index**: The position of an output within a transaction (starting from 0).

## Conclusion

Congratulations! You've now learned how to:

1. Set up a BSV development environment
2. Create private keys and addresses
3. Fetch transaction data from WhatsOnChain
4. Send BSV from one address to another
5. Create and send NFTs on the BSV blockchain
6. Understand the fundamental transaction input and output model

These are the fundamental building blocks for developing applications on the BSV blockchain.