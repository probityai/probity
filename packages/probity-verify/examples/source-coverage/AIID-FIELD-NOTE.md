# AIID report 15: a source coverage question

The public [AIID history](https://incidentdatabase.ai/cite/history/?report_number=15&incident_id=1)
shows a stored article body ending mid-word. A [BBC capture from
2019-06-26 07:25:02](https://web.archive.org/web/20190626072502/https://www.bbc.com/news/blogs-trending-39381889)
contains a later passage about channels removed after the publisher contacted
the platform. AIID's `date_downloaded` is 2019-04-13. The June capture
cannot establish what AIID retrieved in April. The June source and later
record can be compared; the April intake remains `not_established` without
an April capture or original intake record.

The executable fixtures use invented text. The verifier tests literal
inclusion, not who truncated the record or which omissions matter.
