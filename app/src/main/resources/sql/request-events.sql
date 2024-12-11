-- single request logs of interest
-- e.g. Replace <?reqREQ> with 715bde55
SELECT l.*
FROM LOG l
WHERE l.LINE IN (
	SELECT cx.LINE
	FROM REQUEST req
	         JOIN CTX cx
	              ON
	                  req.REQ = '<?reqREQ>'
	                              AND (cx.ASSESS_CTX = req.ASSESS_CTX OR cx.TRACE_MAP = req.TRACE_MAP OR cx.ASSESS_CTX like CONCAT('%', req.ASSESS_CTX))
	                              -- consider adding CONTRAST_CTX to REQUEST (begin and end?) and CTX
	                              AND cx.PATTERN != 'prepareJump'  -- replicates 'savingApp` with less info
UNION
	SELECT cr.LINE FROM
	    REQUEST req
	        JOIN CRUMB cr
	             ON
	                 req.REQ = '<?reqREQ>'
	                 			-- consider adding RESPONSE to REQUEST
	                             AND (cr.REQ = req.REQ OR cr.URL = req.URL)
UNION
	SELECT ht.LINE FROM
	    REQUEST req
	        JOIN HTTP ht
	             ON
	                 req.REQ = '<?reqREQ>'
	                 AND (ht.REQ = req.REQ OR ht.URL = req.URL )
 )
 ORDER BY l.LINE
