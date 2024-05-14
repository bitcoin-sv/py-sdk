import time

from bsv.constants import OpCode
from bsv.script import Script
from bsv.utils import encode_pushdata, encode_int
from helper import create_then_spend


def bin2num():
    print('bin2num')
    # bytes "00 00 00 80 00 00 80" will be converted to integer -2147483648
    locking = Script(encode_pushdata(bytes.fromhex('00 00 00 80 00 00 80')) + OpCode.OP_BIN2NUM + OpCode.OP_EQUAL)
    unlocking = Script(encode_int(-2147483648))
    create_then_spend(locking, unlocking)


def num2bin():
    print('num2bin')
    # integer 2147483648 will be converted to 5 bytes "00 00 00 80 00" (minimal encoding)
    # here we convert to 10 bytes, that would be "00 00 00 80 00 00 00 00 00 00"
    locking = Script(encode_int(2147483648) + encode_int(10) + OpCode.OP_NUM2BIN + OpCode.OP_EQUAL)
    unlocking = Script(encode_pushdata(bytes.fromhex('00 00 00 80 00 00 00 00 00 00')))
    create_then_spend(locking, unlocking)


if __name__ == '__main__':
    bin2num()
    time.sleep(2)
    num2bin()
