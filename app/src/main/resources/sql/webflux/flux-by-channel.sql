SELECT f.*
FROM FLUX f
JOIN (select CHANNEL, min(LINE) AS CHANNEL_START_LINE
	FROM FLUX f
	WHERE CHANNEL IS NOT NULL
	GROUP BY CHANNEL
	ORDER BY CHANNEL_START_LINE) ORDERED_CHANNELS
	ON f.CHANNEL = ORDERED_CHANNELS.CHANNEL
ORDER BY ORDERED_CHANNELS.CHANNEL_START_LINE, f.LINE