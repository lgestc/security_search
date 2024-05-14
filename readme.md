# Security Solution Code Search

Search Security Solution code using semantic queries, such as `custom react hook that implements pagination` to find duplicates,
existing implementation and code examples faster!

## Setup

Clone the repository, then run `npm install`. I am currently only supporting the latest node LTS.

Make sure to setup `process.env.OA` with valid openai API key (also required for searching).

### Running the search against the provided database

Download current database file from [the releases page](https://github.com/lgestc/security_search/releases) and put it into the project root.

After pulling in the database, run `npm start` at the repository root.

Visit `http://localhost:3000` and run your queries.

### Updating the index (for maintainers only)

Make sure to setup `process.env.TARGET_DIRECTORY` pointing at your local `x-pack/plugins/security_solution`.

Then, run `node . reindex` in the project root.

Any files that are not currently indexed (no symbols table entry with up to date `hash`) will be sent over for summarization & embedding,
then related metadata will be updated in the local database.
