import signal


def handler(signal, context):
    res = input("Do you really want to exit? y/n ")
    if res == "y":
        exit(1)


def activate():
    signal.signal(signal.SIGINT, handler)
