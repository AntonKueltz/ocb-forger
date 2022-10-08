# OCB Forger

## About
This is a proof of concept of the attack against OCB2 mode laid out in
the paper [Cryptanalysis of OCB2](https://eprint.iacr.org/2018/1040.pdf).

## Usage

```bash
cd ocb-forger
python3 -m venv ./venv  # optional
source ./venv/bin/activate  # optional
pip3 install -r requirements.txt
python3 {minimal|longer}.py
```
