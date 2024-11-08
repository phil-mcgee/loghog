-- single request terminated by context switch
-- e.g. Replace <?badReq> with 1420789780
SELECT *
FROM LOG
WHERE
    LOG.LINE IN (
        SELECT LOG.LINE
        -- REQUEST BAD_REQ is a request with no end
        FROM REQUEST BAD_REQ
                 JOIN LOG
                      ON
                          BAD_REQ.REQ = <?badReq>
                              AND (
                                  LOG.LINE = BAD_REQ.BEGIN_LINE
                                  OR LOG.LINE = BAD_REQ.CTX_BEG_LINE
                                  OR LOG.LINE = BAD_REQ.TRACE_BEG_LINE
                                  OR LOG.LINE = BAD_REQ.LAST_TRAK_LINE)
UNION
SELECT CHG_CTX.LINE
-- CTX CHG_CTX is any savingApp or prepareJump ConcurrencyContext creation for BAD_REQ
FROM REQUEST BAD_REQ
         JOIN CTX CHG_CTX
              ON
                  BAD_REQ.REQ = <?badReq>
                              AND  CHG_CTX.ASSESS_CTX = BAD_REQ.ASSESS_CTX
                              AND (CHG_CTX.PATTERN = 'savingApp' OR CHG_CTX.PATTERN = 'prepareJump')
UNION
SELECT NEXT_START.LINE FROM
    -- NEXT_START is the first context switch on the BAD_REQ thread (last detected)
    --   after a CHG_CTX
    REQUEST BAD_REQ
        JOIN CTX SAVE_APP
             ON
                 BAD_REQ.REQ = <?badReq>
                             AND SAVE_APP.ASSESS_CTX = BAD_REQ.ASSESS_CTX
                             AND SAVE_APP.PATTERN = 'savingApp'
                JOIN CONT SAVE_APP_CONT
ON SAVE_APP.LINE = SAVE_APP_CONT.LINE
    JOIN MESG APP_SAVE_MESG
    ON APP_SAVE_MESG.LINE = SAVE_APP_CONT.MESG
    JOIN CTX NEXT_START
    ON NEXT_START.LINE IN (
    SELECT min(c.LINE)
    FROM CTX c
    WHERE
    (c.PATTERN = 'onStarted' OR c.PATTERN = 'onStartedNullCtx')
    AND c.THREAD = APP_SAVE_MESG.THREAD
    AND c.LINE > APP_SAVE_MESG.LINE
    )
UNION
SELECT SUBMIT_TASK.LINE FROM
    -- SUBMIT_TASK is the line where the task which triggers the NEXT_START was submitted
    -- frequently we find multiple of these
    REQUEST BAD_REQ
        JOIN CTX SAVE_APP
             ON
                 BAD_REQ.REQ = <?badReq>
                             AND SAVE_APP.ASSESS_CTX = BAD_REQ.ASSESS_CTX
                             AND SAVE_APP.PATTERN = 'savingApp'
                JOIN CONT SAVE_APP_CONT
ON SAVE_APP.LINE = SAVE_APP_CONT.LINE
    JOIN MESG APP_SAVE_MESG
    ON APP_SAVE_MESG.LINE = SAVE_APP_CONT.MESG
    JOIN CTX NEXT_START
    ON NEXT_START.LINE IN (
    SELECT min(c.LINE)
    FROM CTX c
    WHERE
    (c.PATTERN = 'onStarted' OR c.PATTERN = 'onStartedNullCtx')
    AND c.THREAD = APP_SAVE_MESG.THREAD
    AND c.LINE > APP_SAVE_MESG.LINE
    )
    JOIN CTX SUBMIT_TASK
    ON
    SUBMIT_TASK.PATTERN = 'onSubmitted'
    AND SUBMIT_TASK.TASK_OBJ = NEXT_START.TASK_OBJ
    )
