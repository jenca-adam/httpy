import httpy,os,time
a=os.urandom(65538)
wsk = httpy.WebSocket('echo.websocket.events')
wsk.send(a)
time.sleep(1)
g=wsk.recv()
assert g==a
