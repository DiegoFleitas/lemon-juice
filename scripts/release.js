#!/usr/bin/env node

const { readFileSync, writeFileSync, existsSync } = require('node:fs');
const { execFileSync } = require('node:child_process');
const { resolve } = require('node:path');

const rootDir = resolve(__dirname, '..');

function run(...args) {
  execFileSync(args[0], args.slice(1), { stdio: 'inherit', cwd: rootDir });
}

function updateJson(filePath, updater) {
  const fullPath = resolve(rootDir, filePath);
  const raw = readFileSync(fullPath, 'utf8');
  const json = JSON.parse(raw);
  const updated = updater(json);
  writeFileSync(fullPath, JSON.stringify(updated, null, 2) + '\n', 'utf8');
}

function getPreviousTag() {
  try {
    return execFileSync('git', ['describe', '--tags', '--abbrev=0'], { cwd: rootDir }).toString().trim();
  } catch {
    return null;
  }
}

function generateChangelogSection(version) {
  const previousTag = getPreviousTag();
  const range = previousTag ? `${previousTag}..HEAD` : '';
  const gitLogArgs = ['log'];
  if (range) gitLogArgs.push(range);
  gitLogArgs.push('--pretty=format:- %s (%h)');

  const rawLog = execFileSync('git', gitLogArgs, { cwd: rootDir }).toString().trim();
  const changes = rawLog || '- No notable changes.';
  const today = new Date().toISOString().slice(0, 10);

  return `## v${version} - ${today}\n\n${changes}\n`;
}

function updateChangelog(version) {
  const changelogPath = resolve(rootDir, 'CHANGELOG.md');
  const header = '# Changelog';
  const section = generateChangelogSection(version);

  if (!existsSync(changelogPath)) {
    const content = `${header}\n\n${section}\n`;
    writeFileSync(changelogPath, content, 'utf8');
    return;
  }

  const existing = readFileSync(changelogPath, 'utf8');

  if (!existing.startsWith(header)) {
    const content = `${header}\n\n${section}\n${existing}`;
    writeFileSync(changelogPath, content, 'utf8');
    return;
  }

  const rest = existing.slice(header.length).trimStart();
  const content = `${header}\n\n${section}\n${rest}`;
  writeFileSync(changelogPath, content.trimEnd() + '\n', 'utf8');
}

function main() {
  const args = process.argv.slice(2).filter((arg) => arg !== '--');
  const version = args[0];

  if (!version) {
    console.error('Usage: pnpm release -- <version>');
    process.exit(1);
  }

  if (!/^\d+\.\d+\.\d+$/.test(version)) {
    console.error(`Invalid version "${version}". Expected format: X.Y.Z (e.g., 0.2.0).`);
    process.exit(1);
  }

  const tag = `v${version}`;

  const status = execFileSync('git', ['status', '--porcelain'], { cwd: rootDir }).toString().trim();
  if (status) {
    console.error('Working tree is not clean. Commit or stash your changes before running the release script.');
    process.exit(1);
  }

  console.log(`Updating package.json and manifest.json to version ${version}...`);

  updateJson('package.json', (pkg) => {
    pkg.version = version;
    return pkg;
  });

  updateJson('manifest.json', (manifest) => {
    manifest.version = version;
    return manifest;
  });

  console.log('Updating CHANGELOG.md...');
  updateChangelog(version);

  console.log('Creating release commit and tag...');
  run('git', 'add', 'package.json', 'manifest.json', 'CHANGELOG.md');
  run('git', 'commit', '-m', `Release ${tag}`);
  run('git', 'tag', tag);

  console.log();
  console.log('Done.');
  console.log('Next steps:');
  console.log('  git push origin main --tags');
  console.log(`This will trigger the GitHub Actions release workflow for ${tag}.`);
}

main();
