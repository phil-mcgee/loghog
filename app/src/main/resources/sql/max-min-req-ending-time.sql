SELECT nding.*, MIN_REQT.LINE MIN_TIME_LINE, MAX_REQT.LINE MAX_TIME_LINE, (MAX_REQT.LINE - MIN_REQT.LINE) DIFF
FROM (SELECT * FROM HTTP WHERE PATTERN = 'reqEnding') nding
         JOIN HTTP MIN_REQT
              ON MIN_REQT.LINE IN (
                  SELECT min(LINE)
                  FROM HTTP
                  WHERE URL = nding.URL
                    AND PATTERN = 'lmReqTime'
                    AND LINE > nding.LINE
                    AND THREAD = nding.THREAD
              )
         JOIN HTTP MAX_REQT
              ON
                  MAX_REQT.LINE IN (
                      SELECT max(LINE)
                      FROM HTTP
                      WHERE URL = nding.URL
                        AND PATTERN = 'lmReqTime'
                        AND LINE > nding.LINE
                        AND THREAD = nding.THREAD
                  )