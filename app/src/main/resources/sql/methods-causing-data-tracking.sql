-- methods causing data tracking
SELECT ENTRY, count(*)
FROM log
WHERE line IN (
	SELECT tos.line
	FROM (
		SELECT m.*
		FROM MESG m
		JOIN THREAD t
		ON t.line IN (SELECT line FROM trak)
		AND m.line = t.NEXT_IN_THREAD
		AND m.MESSAGE LIKE 'TRAC%'
	) code_event
	JOIN CONT tos
	ON tos.mesg = code_event.line
	AND tos.line = (SELECT min(line) FROM cont WHERE cont.mesg = code_event.line)
)
GROUP BY ENTRY