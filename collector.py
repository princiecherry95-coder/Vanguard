"""Local SOC collectors: no cloud dependency, bounded and explicit."""
from __future__ import annotations
import socket, threading, time
from collections import deque
from pathlib import Path
from typing import Callable

class LocalLogCollector:
    def __init__(self,max_lines=10000):
        self.lines=deque(maxlen=max_lines); self.running=False; self._thread=None
    def tail_file(self,path:str,interval:float=0.5,callback:Callable[[str],None]|None=None):
        p=Path(path)
        if not p.exists(): raise FileNotFoundError(path)
        self.running=True
        def run():
            with p.open("r",encoding="utf-8",errors="replace") as f:
                f.seek(0,2)
                while self.running:
                    line=f.readline()
                    if line:
                        clean=line.rstrip("\r\n"); self.lines.append(clean)
                        if callback: callback(clean)
                    else: time.sleep(interval)
        self._thread=threading.Thread(target=run,daemon=True); self._thread.start(); return self._thread
    def snapshot(self): return list(self.lines)
    def stop(self): self.running=False

class SyslogUDPCollector:
    def __init__(self,host="127.0.0.1",port=5514,max_lines=10000):
        self.host,self.port=host,port; self.lines=deque(maxlen=max_lines); self.running=False; self._thread=None
    def serve(self,callback:Callable[[str],None]|None=None):
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); sock.bind((self.host,self.port)); sock.settimeout(0.5); self.running=True
        try:
            while self.running:
                try:data,_=sock.recvfrom(65535)
                except socket.timeout:continue
                line=data.decode("utf-8","replace").rstrip("\r\n"); self.lines.append(line)
                if callback: callback(line)
        finally:sock.close()
    def start(self,callback:Callable[[str],None]|None=None):
        self._thread=threading.Thread(target=self.serve,args=(callback,),daemon=True); self._thread.start(); return self._thread
    def snapshot(self): return list(self.lines)
    def stop(self): self.running=False
