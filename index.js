import Database from "better-sqlite3";
import * as sqlite_vss from "sqlite-vss";
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'path';
import crypto from 'crypto'
import OpenAI from 'openai'
import z from 'zod';
import express from 'express';

const API_KEY = process.env.OA;

if (!API_KEY) {
  throw new Error("setup OA key with your open ai api key");
}

const EMBEDDING_MODEL = 'text-embedding-ada-002';

const COMPLETIONS_MODEL = 'gpt-3.5-turbo-0125';

const DATABASE_NAME = 'security_solution.db';

const PROMPT = `You are helping to document the provided source, providing json metadata for the source code you see.
You should analyze the source code looking at functions, classes and constants available.
Generate output as json array at "symbols" key, where each source code unit is represented as object with the following keys:
- symbolName - name of the code unit described
- line - line where the code starts
- description - short description of what the unit of code does. it should also mention the use case (in one sentence).
  this description will be turned into embedding, so make it vector search friendly. It should be a markdown text without any nested json.
`;

const TARGET_DIRECTORY = process.env.TARGET_DIRECTORY; 

const responseSchema = z.object({
  symbols: z.array(z.object({symbolName: z.string(), line: z.number(), description: z.string()}))
});

const openai = new OpenAI({
  apiKey: API_KEY,
});

const DB = new Database(DATABASE_NAME);
sqlite_vss.load(DB);

async function traverseFiles(directory) {
  const files = await fs.readdir(directory);
  const result = [];

  for (const file of files) {
    if (file.includes("node_modules")) {
      continue;
    }
    if (file.includes(".git")) {
      continue;
    }

    const filePath = path.join(directory, file);
    const stats = await fs.stat(filePath);

    if (stats.isFile()) {
      result.push(filePath);
    } else if (stats.isDirectory()) {
      result.push(...await traverseFiles(filePath));
    }
  }

  return result
}

const sha1 = path => new Promise((resolve, reject) => {
	const hash = crypto.createHash('sha1')
	const rs = fsSync.createReadStream(path)
	rs.on('error', reject)
	rs.on('data', chunk => hash.update(chunk))
	rs.on('end', () => resolve(hash.digest('hex')))
})

const isSourceFile = (filename) => {
  if (filename.includes('test')) {
    return false;
  }

  if (filename.includes('translation')) {
    return false;
  }

  if (filename.includes('mock')) {
    return false;
  }

  if (filename.includes('types')) {
    return false;
  }

  if (filename.includes('constants')) {
    return false;
  }

  if (filename.includes('stories')) {
    return false;
  }

  if (filename.includes('style')) {
    return false;
  }

  if (filename.includes('storybook')) {
    return false;
  }

  if (filename.includes('gen.ts')) {
    return false;
  }

  return filename.endsWith('.ts') || filename.endsWith('.tsx') || filename.endsWith('.jsx') || filename.endsWith('.js');
}

const generateEmbedding = async (input) => {
  const {data: [{embedding}]} = await openai.embeddings.create({input, model: EMBEDDING_MODEL});

  return embedding;
}

const generateMetadata = async (input) => {
  const baseMessages = [
      {
        role: "system",
        content: PROMPT,
      },
      { role: "user", content: input },
  ];

  const completionRequest = {

    messages: [
      ...baseMessages,
    ],
    model: COMPLETIONS_MODEL,
    response_format: { type: "json_object" },
  }

  const completion = await openai.chat.completions.create(completionRequest);

  const parsed = JSON.parse(completion.choices[0].message.content);

  const parseResult = responseSchema.safeParse(parsed);

  if (parseResult.success) {
    return parseResult.data;
  } else {
    throw new Error('could not parse completion response');
  }
};

const readFile = (filename) => fs.readFile(filename, {encoding: 'utf-8'});

const checkIfFileExistsInTheFilesystem = (directoryPath, filename) => fsSync.existsSync(path.join(directoryPath, filename))

const checkIfFileHashExists = (hash) => {
  const fileRecord = DB.prepare("select * from symbols where hash = ? limit 1").pluck().get(hash);

  return !!fileRecord;
}

const checkIfFileNameIsKnown = (filename) => {
  const fileRecord = DB.prepare("select * from symbols where filename = ? limit 1").pluck().get(filename);

  return fileRecord;
}

const buildIndex = async (directoryPath) => {
  if (!directoryPath.includes('x-pack/plugins/security_solution')) {
    throw new Error('invalid path to security_solution plugin')
  }

  const version = DB.prepare("select vss_version()").pluck().get();

  DB.prepare(`
    create virtual table if not exists embeddings using vss0(
      a(1536)
    )
  `).run();

  DB.prepare(`
    create table if not exists symbols (
      filename TEXT,
      hash TEXT,
      metadata TEXT,
      embedding_id INT
    )
  `).run();

  const knownSymbols = DB.prepare('SELECT * FROM symbols').all();

  let outdated = 0;

  // NOTE: check if the file does not exist - remove it from the database if its not there
  for (const knownSymbol of knownSymbols) {
    if (checkIfFileExistsInTheFilesystem(directoryPath, knownSymbol.filename)) {
      continue;
    }

    outdated++;

    DB.prepare('DELETE FROM embeddings WHERE rowid IN (SELECT rowid FROM symbols WHERE filename = ?)').run(knownSymbol.filename);

    DB.prepare('DELETE FROM symbols WHERE filename = ?').run(knownSymbol.filename);
  }

  console.info('cleared ' + outdated + ' outdated symbols');

  const files = await traverseFiles(directoryPath);
  const sourceFiles = files.filter(isSourceFile);

  console.log(`vss version ${version}`)
  console.log(`index files in ${directoryPath}`);
  console.log('files count', files.length);
  console.log('meaningful source files count', sourceFiles.length);

  let i = Date.now();

  let progress = 0;

  for (const file of sourceFiles) {
    progress++;

    const hash = await sha1(file)
    const code = await readFile(file);
    const relativeFile = file.replace(directoryPath, '');

    if (checkIfFileHashExists(hash)) {
      console.info(relativeFile + ' already known, skipping');
      continue;
    }

    // if hash does not exist, the file has changed
    try {
      const knownFile = checkIfFileNameIsKnown(relativeFile);

      const metadata = await generateMetadata(code);

      if (knownFile) {
        DB.prepare('DELETE FROM embeddings WHERE rowid IN (SELECT rowid FROM symbols WHERE filename = ?)').run(relativeFile);
      } 

      for (const item of metadata.symbols) {
        if (item.symbolName.includes('export')) {
          continue;
        }

        if (item.symbolName.includes('import')) {
          continue;
        }

        if (item.symbolName.includes('interface')) {
          continue;
        }

        const embedding = await generateEmbedding(item.symbolName + ' ' + item.description);
        console.info('creating new symbols record for ' + relativeFile + ' ' + item.symbolName);
        i++;

        DB.prepare('INSERT INTO embeddings(rowid, a) VALUES(?, ?)').run(i, JSON.stringify(embedding));
        DB.prepare('INSERT INTO symbols(embedding_id, filename, hash, metadata) VALUES(?, ?, ?, ?)').run(i, relativeFile, hash, JSON.stringify(item));
      }
    } catch (error) {
      console.error(error);
    }

    console.log('progress: ' + progress + '/'+ sourceFiles.length);
  }
}

const runQuery = async (query) => {
  // NOTE: this is where the "client" side of this utility will start
  const queryAsEmbedding = await generateEmbedding(query);

  const allData = DB.prepare(`
    SELECT e.*, f.filename, f.metadata FROM (
        SELECT
          rowid,
          distance
        FROM embeddings
        WHERE vss_search(a, ?)
        LIMIT 20
      )
    e JOIN symbols f ON f.embedding_id = e.rowid
    order by e.distance ASC
  `).all(JSON.stringify(queryAsEmbedding));

  return allData
}

const args = process.argv.slice(2);

if (args.length > 0) {
  if (args[0] === 'reindex') {
    await buildIndex(TARGET_DIRECTORY);
  } else {
    console.log('usage: node . reindex to reindex the database with current data')
  }
} else {
  if (!fsSync.existsSync(DATABASE_NAME)) {
    throw new Error('database file does not exist. consult the readme on how to configure the database correctly');
  }

  const app = express();

  const defaultQuery = 'component that renders field values';

  // GET route
  app.get('/', async (req, res) => {
    const html = `
      <html data-theme="dark">
        <head>
          <title>Security Solution Codebase Search</title>
          <script src="https://unpkg.com/htmx.org@1.9.12"></script>
          <link
            rel="stylesheet"
            href="https://cdn.jsdelivr.net/npm/bulma@1.0.0/css/bulma.min.css"
          >
        </head>
        <body>
            <div class="htmx-indicator" style="position: fixed; left: 25%; top: 50%; text-align: center; z-index: 2; width: 50%; height: 2rem;"> 
              <progress class="progress is-large is-info" max="100">60%</progress>
            </div>
            <div class="container">
                <div class="block"></div>

                <h1 class="title">Security Solution Codebase Search</h1>

                <div class="block">
                      <input class="input" type="search" 
                            name="search" placeholder="Type in your codebase query in natural language" 
                            hx-get="/search" 
                            hx-trigger="input changed delay:500ms, search" 
                            hx-indicator=".htmx-indicator"
                            hx-target="#search-results">
                </div>

                <div id="search-results"></div>
            </div>
        </body>
      </html>
    `;
    res.send(html);
  });

  app.get('/search', async (req, res) => {
    const search = req.query.search || defaultQuery;

    const results = await runQuery(search);

    const html = `
      <div>
        ${results.map(result => {
          const parsed = JSON.parse(result.metadata);
          return `<div class="box">
            <h3 class="title is-5">${parsed.symbolName}</h3>
            <p>${parsed.description}</p>
            <code>${result.filename}:${parsed.line}</code>
          </div>`;
        }).join('')}
      </div>
    `;
    res.send(html);
  });

  // Start the server
  app.listen(3000, () => {
    console.log('browse database at http://localhost:3000');
  });
}
