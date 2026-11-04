// Keeps the published CJS type declaration at dist/lib.cjs/types/index.d.ts,
// the path that package.json "types" has always pointed to.
import { copyFileSync, mkdirSync } from "node:fs";

mkdirSync("dist/lib.cjs/types", { recursive: true });
copyFileSync("dist/lib.cjs/index.d.ts", "dist/lib.cjs/types/index.d.ts");
