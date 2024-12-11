-- server-channel-pollution.sql
SELECT f.LINE, f."TIMESTAMP", f.THREAD, f.CHANNEL , f.PATTERN, f.REQ, f.URL, f.ASSESS_CTX, f.TASK_OBJ, f.WRAPPED
FROM FLUX f
WHERE
	CHANNEL like 'NioServerSocketChannel%'
	OR ASSESS_CTX IN
(
	SELECT ASSESS_CTX
	FROM FLUX
	WHERE
	CHANNEL like 'NioServerSocketChannel%'
)
OR CHANNEL IS NULL AND THREAD = 'reactor-http-nio-1'
ORDER BY LINE
