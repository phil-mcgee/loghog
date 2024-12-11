SELECT sub.LINE, sub.THREAD, sub.TASK_CLASS, sub.TASK_OBJ, sub.TRACE_MAP, sub.PATTERN, req.BEGIN_LINE, req.BEGIN_THREAD, req.REQ, req.URL, req.TRACE_MAP, req.END_THREAD
FROM REQUEST req
JOIN CTX sub
ON
  (sub.ASSESS_CTX = req.ASSESS_CTX OR sub.TRACE_MAP = req.TRACE_MAP)
  AND sub.PATTERN = 'onSubmitted'
  -- every(?) request seems to leave these two task types unexecuted
  AND sub.TASK_CLASS != 'reactor.netty.http.HttpOperations$PostHeadersNettyOutbound'
  AND sub.TASK_CLASS != 'reactor.netty.http.server.HttpServerOperations$$Lambda$890/0x0000000840884840'
  AND NOT EXISTS (
    SELECT LINE
    FROM CTX
    WHERE
        sub.TASK_OBJ = TASK_OBJ
        AND (PATTERN = 'onStarted' OR PATTERN = 'onStartedNullCtx')
  )
ORDER BY req.BEGIN_LINE, sub.LINE