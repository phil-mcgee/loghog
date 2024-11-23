-- ctx-from-first-assess.sql
SELECT *
FROM CTX
WHERE line >= (
SELECT min(line)
FROM CTX
WHERE
ASSESS_CTX IS NOT NULL AND ASSESS_CTX != 'null'
)