-- e.g. Replace <?traceMap> with '355e4f4a'
SELECT l.*
FROM log l
WHERE l.line IN (
	SELECT t.line
	FROM trak t
	WHERE
	t.trace_map=<?traceMap>
	UNION
	SELECT plug.line
	FROM trak t2
	JOIN mesg plug
	ON t2.trace_map=<?traceMap>
	AND plug.line IN (
		SELECT min(line)
		FROM MESG
		WHERE thread = t2.thread
		AND line > t2.line
	)
	UNION
	SELECT c.line
	from cont c
	WHERE c.mesg IN (
		SELECT p2.line
		FROM trak t3
		JOIN mesg p2
		ON t3.trace_map=<?traceMap>
		AND p2.line IN (
			SELECT min(line)
			FROM MESG
			WHERE thread = t3.thread
			AND line > t3.line
		)
	)
)
