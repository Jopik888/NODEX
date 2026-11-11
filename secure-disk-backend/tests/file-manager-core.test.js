import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isFolderRecord, normalizeDriveName, driveItemKey, getDriveChildren,
  getDriveFolderPath, getDescendantFolderIds, collectFolderContents,
  canMoveFolder, getRelativePath, getRelativeFolderPath, isSafeArchivePath, listArchiveChildren,
  buildFolderUploadPlan, buildIncomingFolderMergePlan,
} from '../../secure-disk/file-manager-core.js';

const tree = [
  { id: 'a', type: 'folder', name: 'Документы', parentId: null },
  { id: 'b', type: 'folder', name: 'Работа', parentId: 'a' },
  { id: 'c', type: 'folder', name: 'Отчёты', parentId: 'b' },
  { id: 'd', type: 'folder', name: 'Фото', parentId: null },
  { cid: 'cid-1', name: 'report.pdf', parentId: 'c' },
  { cid: 'cid-2', name: 'photo.jpg', parentId: 'd' },
  { cid: 'cid-3', name: 'root.txt', parentId: null },
];

test('folder recognition, identity and direct children', () => {
  assert.equal(isFolderRecord(tree[0]), true);
  assert.equal(isFolderRecord(tree[4]), false);
  assert.equal(driveItemKey(tree[0]), 'folder:a');
  assert.equal(driveItemKey(tree[4]), 'file:cid-1');
  assert.deepEqual(getDriveChildren(tree, 'a').map(x => x.id), ['b']);
});

test('folder path and recursive contents', () => {
  assert.deepEqual(getDriveFolderPath(tree, 'c').map(x => x.name), ['Документы', 'Работа', 'Отчёты']);
  const contents = collectFolderContents(tree, 'a');
  assert.deepEqual([...contents.folderIds].sort(), ['a', 'b', 'c']);
  assert.deepEqual(contents.files.map(x => x.cid), ['cid-1']);
  assert.equal(getRelativePath(tree, 'a', tree[4]), 'Работа/Отчёты/report.pdf');
  assert.equal(getRelativeFolderPath(tree, 'a', 'c'), 'Работа/Отчёты');
  assert.throws(() => getRelativeFolderPath(tree, 'b', 'd'));
});

test('move validation blocks cycles', () => {
  assert.equal(canMoveFolder(tree, 'a', 'd'), true);
  assert.equal(canMoveFolder(tree, 'a', 'c'), false);
  assert.equal(canMoveFolder(tree, 'b', 'b'), false);
});

test('name validation rejects traversal and separators', () => {
  assert.equal(normalizeDriveName('  Папка  '), 'Папка');
  for (const value of ['', '..', '.', '../secret', 'a/b', 'a\\b']) assert.throws(() => normalizeDriveName(value));
});

test('archive paths reject traversal and absolute paths', () => {
  assert.equal(isSafeArchivePath('docs/report.pdf'), true);
  assert.equal(isSafeArchivePath('../secret.txt'), false);
  assert.equal(isSafeArchivePath('/etc/passwd'), false);
  assert.equal(isSafeArchivePath('C:/windows/file'), false);
});

test('ZIP listing exposes only immediate children', () => {
  const entries = [
    { name: 'docs/', dir: true },
    { name: 'docs/reports/', dir: true },
    { name: 'docs/reports/a.pdf', dir: false },
    { name: 'docs/readme.txt', dir: false },
    { name: '../outside.txt', dir: false },
  ];
  const root = listArchiveChildren(entries);
  assert.deepEqual(root.map(x => `${x.dir ? 'd' : 'f'}:${x.name}`), ['d:docs']);
  const nested = listArchiveChildren(entries, 'docs');
  assert.deepEqual(nested.map(x => `${x.dir ? 'd' : 'f'}:${x.name}`), ['d:reports', 'f:readme.txt']);
});

test('folder upload plan retains nested structure without archiving files', () => {
  const file = { name: 'report.pdf', size: 10 };
  const plan = buildFolderUploadPlan('Данные', 'parent-1', [{ file, relativePath: 'Работа/Отчёты/report.pdf' }], ['Пустая']);
  assert.equal(plan.rootName, 'Данные');
  assert.equal(plan.parentId, 'parent-1');
  assert.deepEqual(plan.directories, ['Пустая', 'Работа', 'Работа/Отчёты']);
  assert.equal(plan.files[0].relativeDir, 'Работа/Отчёты');
  assert.equal(plan.files[0].name, 'report.pdf');
});


test('folder sync plan sorts parents before children and accepts child files only after ancestors', () => {
  const incoming = [
    { id: 'child', type: 'folder', name: 'Вложенная', parentId: 'parent' },
    { id: 'parent', type: 'folder', name: 'Главная', parentId: null },
  ];
  const plan = buildIncomingFolderMergePlan([], incoming);
  assert.deepEqual(plan.map(folder => folder.id), ['parent', 'child']);
});

test('folder sync plan rejects children of folders rejected by name collision', () => {
  const existing = [{ id: 'existing', type: 'folder', name: 'Занято', parentId: null }];
  const incoming = [
    { id: 'colliding', type: 'folder', name: 'Занято', parentId: null },
    { id: 'orphan-child', type: 'folder', name: 'Внутри', parentId: 'colliding' },
  ];
  assert.deepEqual(buildIncomingFolderMergePlan(existing, incoming), []);
});

test('folder sync plan rejects cycles, missing parents and deleted parent trees', () => {
  const incoming = [
    { id: 'a', type: 'folder', name: 'A', parentId: 'b' },
    { id: 'b', type: 'folder', name: 'B', parentId: 'a' },
    { id: 'orphan', type: 'folder', name: 'Orphan', parentId: 'missing' },
    { id: 'child', type: 'folder', name: 'Child', parentId: 'deleted' },
  ];
  assert.deepEqual(buildIncomingFolderMergePlan([], incoming, ['deleted']), []);
});
