from bsv.script.script import Script
from bsv.script.spend import Spend
from .spend_vector import SPEND_VALID_CASES


def test():
    for case in SPEND_VALID_CASES:
        spend = Spend({
            'sourceTXID': '0000000000000000000000000000000000000000000000000000000000000000',
            'sourceOutputIndex': 0,
            'sourceSatoshis': 1,
            'lockingScript': Script(case[1]),
            'transactionVersion': 1,
            'otherInputs': [],
            'outputs': [],
            'inputIndex': 0,
            'unlockingScript': Script(case[0]),
            'inputSequence': 0xffffffff,
            'lockTime': 0
        })
        assert spend.validate()
