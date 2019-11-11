# dynamite_nsm.services.filebeat

## FileBeatProcess
```python
FileBeatProcess(self)
```

An interface for start|stop|status|restart of the Filebeat process

### start
```python
FileBeatProcess.start(self, stdout=False)
```

Start the Filebeat daemon
- *param:* stdout: Print output to console
- *return:* True if started successfully

### status
```python
FileBeatProcess.status(self)
```

Check the status of the FileBeat process

- *return:* A dictionary containing the run status and relevant configuration options

### stop
```python
FileBeatProcess.stop(self, stdout=False)
```

Stop the LogStash process

- *param:* stdout: Print output to console
- *return:* True if stopped successfully

