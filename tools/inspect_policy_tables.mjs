import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const depsNodeModules =
  "C:/Users/woghd/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules";
const require = createRequire(`${depsNodeModules}/`);
const { FileBlob, SpreadsheetFile } = await import(
  pathToFileURL(require.resolve("@oai/artifact-tool")).href
);

const inputPath =
  process.argv[2] ??
  "C:/Users/woghd/Desktop/캡스톤/zerotrust_policy_access_tables.xlsx";
const sheetName = process.argv[3];
const range = process.argv[4];

const workbook = await SpreadsheetFile.importXlsx(await FileBlob.load(inputPath));

const inspectOptions = {
  kind: "workbook,sheet,table",
  include: "id,name,values,formulas",
  tableMaxRows: 140,
  tableMaxCols: 24,
  tableMaxCellChars: 120,
  maxChars: 80000,
};

if (sheetName) {
  inspectOptions.sheetId = sheetName;
}
if (range) {
  inspectOptions.range = range;
}

const sheets = await workbook.inspect(inspectOptions);

console.log(sheets.ndjson);
