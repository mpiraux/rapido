import json
import os
import subprocess

rapido_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(*args, stdout='json', stderr=True, shell=True, env=None, timeout=None):
    kwargs = {}
    if not stderr:
        kwargs['stderr'] = subprocess.DEVNULL
    if stdout == 'json':
        kwargs['stdout'] = subprocess.PIPE
    if env:
        kwargs['env'] = os.environ.copy()
        kwargs['env'].update(env)

    p = subprocess.Popen(*args, universal_newlines=True, shell=True, **kwargs)
    try:
        code = p.wait(timeout=timeout)
        if code != 0 or not stdout:
            return code
        try:
            return json.loads(p.stdout.read())
        except:
            return code
    except:
        p.terminate()
        return 'timeout'
