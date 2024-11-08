SELECT nding.*, REQT.LINE
FROM (SELECT * FROM HTTP WHERE PATTERN = 'reqEnding') nding
         JOIN HTTP REQT
              ON
                  REQT.LINE IN (
                      SELECT h.LINE
                      FROM HTTP h
                      WHERE h.URL = nding.URL
                        AND h.PATTERN = 'lmReqTime'
                        AND h.LINE > nding.LINE
                        AND h.THREAD = nding.THREAD