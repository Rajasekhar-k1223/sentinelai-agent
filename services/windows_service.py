"""
Windows service wrapper example.
Requires pywin32 and admin to install the service.
This script will run agent_main.py as the service's process.
"""
import os
import sys
import subprocess
import win32serviceutil
import win32service
import win32event
import servicemanager

AGENT_MAIN = os.path.join(os.path.dirname(__file__), "..", "agent_main.py")

class SentinelService(win32serviceutil.ServiceFramework):
    _svc_name_ = "SentinelAIAgent"
    _svc_display_name_ = "SentinelAI Agent"

    def __init__(self, args):
        super().__init__(args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.proc = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self.proc:
            self.proc.terminate()
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        # start the agent in a subprocess
        python = sys.executable
        self.proc = subprocess.Popen([python, AGENT_MAIN])
        servicemanager.LogInfoMsg("SentinelAI Agent service started.")
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(SentinelService)
