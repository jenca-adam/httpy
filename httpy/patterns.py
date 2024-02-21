import re

URLPATTERN = re.compile(
    r"^(?P<scheme>[a-z]+)://(?P<host>[^/:]*)(:(?P<port>(\d+)?))?/?(?P<path>.*)$"
)
STATUSPATTERN = re.compile(
    rb"(?P<VERSION>.*)\s*(?P<status>\d{3})\s*(?P<reason>[^\r\n]*)"
)
STRTIME_PATTERN = "%a, %d %b% Y, %H:%M:%S%Z"
