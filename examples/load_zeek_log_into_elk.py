from parsezeeklogs import ParseZeekLogs

ParseZeekLogs.batch_to_elk("http.log", meta={"source": "http"})
