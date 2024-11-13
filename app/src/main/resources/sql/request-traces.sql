-- single request logs of interest
-- e.g. Replace <?reqREQ> with 715bde55
SELECT l.*
FROM LOG l
WHERE l.LINE IN (
 	SELECT tr.LINE FROM
 	    REQUEST req
 	        JOIN TRAK tr
 	             ON
 	                 req.REQ = '<?reqREQ>'
 	                 AND tr.TRACE_MAP = req.TRACE_MAP
 )
 ORDER BY l.LINE
