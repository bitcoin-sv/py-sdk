from bsv.hello import greetings


def test_greetings():
    assert greetings() == 'Hello, World!'
