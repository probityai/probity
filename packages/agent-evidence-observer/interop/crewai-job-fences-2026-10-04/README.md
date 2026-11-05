# CrewAI job fences

The pinned CrewAI job contract runs through 17 direct admission cases and three real threaded flows. The source is [738c8e19](https://github.com/crewAIInc/crewAI/commit/738c8e19e35c2888d8e0663bc5cc45c5acf6ac2d). The producing operation is run by the operator's runtime; this directory holds the installed reader, the retained CI packet from the last producing run, the setup attempts and the reader's fault controls. Source bytes of the producing run are held as digests in `retained/WITHHELD-SOURCES.json`.

The native job record, Observer body effects and explicit foreground publication stay separate. The reader reconstructs the retained inputs and callbacks without CrewAI installed. Actual Verify consumes three body-effect absence projections twice.

The [workflow](../../../../.github/workflows/package-observer-crewai-job-fences.yml) installs the reader from `requirements-runtime-reader.lock`, checks the retained record with public code, runs the 30 semantic controls over the retained packet and runs the Verify consumer.

These are author-operated finite source qualifications with PEER witness storage. The earlier 16 rows and prospective eight-task study retain their separate status.
