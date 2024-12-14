SELECT * FROM log WHERE line IN (
	SELECT BEGIN_LINE FROM REQUEST r WHERE r.URL = '/auto-binding/v1_0/autobind-unsafe'
	UNION
	SELECT END_LINE FROM REQUEST r WHERE r.URL = '/auto-binding/v1_0/autobind-unsafe'
	UNION
	SELECT c.LINE
	FROM CTX c
	JOIN REQUEST r
	ON r.URL = '/auto-binding/v1_0/autobind-unsafe'
	AND c.THREAD = r.BEGIN_THREAD
	AND c.LINE >= r.BEGIN_LINE AND c.LINE <= r.END_LINE
	UNION
	SELECT t.LINE
	FROM trak t
	JOIN REQUEST r
	ON r.URL = '/auto-binding/v1_0/autobind-unsafe'
	AND t.TRACE_MAP = r.TRACE_MAP
	AND t.LINE = (SELECT max(line) FROM trak WHERE TRACE_MAP = r.TRACE_MAP)
	UNION
	SELECT f.LINE
	FROM flux f
	JOIN REQUEST r
	ON r.URL = '/auto-binding/v1_0/autobind-unsafe'
	AND f.TRACE_MAP = r.TRACE_MAP
	UNION
	SELECT v.LINE
	FROM vuln v
	WHERE v.URL = '/auto-binding/v1_0/autobind-unsafe'
) ORDER BY LINE
