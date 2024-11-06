-- context switch terminated request tracking
SELECT *
FROM LOG
WHERE
    LOG.LINE IN (
        SELECT LOG.LINE
        FROM REQUEST BAD_REQ
                 JOIN LOG
                      ON
                          BAD_REQ.END_LINE IS NULL
                              AND (
                              LOG.LINE = BAD_REQ.BEGIN_LINE
                                  OR LOG.LINE = BAD_REQ.CTX_BEG_LINE
                                  OR LOG.LINE = BAD_REQ.TRACE_BEG_LINE
                                  OR LOG.LINE = BAD_REQ.LAST_TRAK_LINE)
        UNION
        SELECT CHG_CTX.LINE
        FROM REQUEST BAD_REQ
                 JOIN CTX CHG_CTX
                      ON
                          BAD_REQ.END_LINE IS NULL
                              AND  CHG_CTX.ASSESS_CTX = BAD_REQ.ASSESS_CTX
                              AND (CHG_CTX.PATTERN = 'savingApp' OR CHG_CTX.PATTERN = 'prepareJump')
        UNION
        SELECT PREVIOUS.LINE
        FROM REQUEST BAD_REQ
                 JOIN CTX SAVE_APP
                      ON
                          BAD_REQ.END_LINE IS NULL
                              AND SAVE_APP.ASSESS_CTX = BAD_REQ.ASSESS_CTX
                              AND SAVE_APP.PATTERN = 'savingApp'
                 JOIN CONT PREVIOUS
                      ON SAVE_APP.LINE = PREVIOUS.LINE
        UNION
        SELECT NEXT_START.LINE FROM
            REQUEST BAD_REQ
                JOIN CTX SAVE_APP
                     ON
                         BAD_REQ.END_LINE IS NULL
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
        SELECT NEXT_START.LINE FROM
            REQUEST BAD_REQ
                JOIN CTX SAVE_APP
                     ON
                         BAD_REQ.END_LINE IS NULL
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
            REQUEST BAD_REQ
                JOIN CTX SAVE_APP
                     ON
                         BAD_REQ.END_LINE IS NULL
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
