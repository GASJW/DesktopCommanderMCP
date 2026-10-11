import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../');
const gateway=readFileSync(path.join(root,'.github/workflows/vps-commander-gateway.yml'),'utf8');
const spelling=readFileSync(path.join(root,'.github/workflows/codespell.yml'),'utf8');

test('branch-protection required checks always run for docs-only and stacked PRs',()=>{
  assert.match(gateway,/^on:\n  pull_request:\n  push:\n    branches:\n      - main$/m);
  assert.match(gateway,/^  gateway-tests:$/m);
  assert.doesNotMatch(gateway,/^  pull_request:\n    paths:/m);
  assert.match(spelling,/^  pull_request:$/m);
  assert.match(spelling,/^    name: Check for spelling errors$/m);
  assert.match(spelling,/^          skip: \.\/docs(?:,.*)?$/m);
});
