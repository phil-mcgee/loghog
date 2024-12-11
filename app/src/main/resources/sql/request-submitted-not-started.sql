-- e.g. Replace <?reqREQ> with 715bde55
SELECT sub.*
FROM REQUEST req
JOIN CTX sub
ON
    req.REQ = '<?reqREQ>'
    AND (sub.ASSESS_CTX = req.ASSESS_CTX OR sub.TRACE_MAP = req.TRACE_MAP)
    AND sub.PATTERN = 'onSubmitted'
    AND NOT EXISTS (
        SELECT LINE
        FROM CTX
        WHERE
            sub.TASK_OBJ = TASK_OBJ
            AND (PATTERN = 'onStarted' OR PATTERN = 'onStartedNullCtx')
    )