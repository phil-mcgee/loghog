-- tracking code events
SELECT code_event.*
FROM MESG code_event
JOIN THREAD t
ON t.line IN (SELECT line FROM trak)
AND code_event.line = t.NEXT_IN_THREAD
AND code_event.MESSAGE LIKE 'TRAC%'