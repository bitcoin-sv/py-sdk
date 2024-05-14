import random

from bsv.constants import OpCode
from bsv.script import Script
from bsv.utils import encode_int
from helper import create_then_spend

a = random.randint(-128, 128)
b = random.randint(-128, 128)
print(a, b)

# locking script requires the result of a + b
locking = Script(encode_int(a) + encode_int(b) + OpCode.OP_ADD + OpCode.OP_EQUAL)
# unlocking script provides the result
unlocking = Script(encode_int(a + b))

create_then_spend(locking, unlocking)
