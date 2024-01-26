if ! (ls httpy >/dev/null);then
       	ln -sf ../httpy httpy;
fi
python3 -m pytest -v test_httpy.py
python3 -m h2tests
