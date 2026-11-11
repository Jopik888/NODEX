export function isFolderRecord(item) {
    return Boolean(item && (item.type === 'folder' || item.isFolder === true));
}

export function normalizeDriveName(value, label = 'Имя') {
    if (typeof value !== 'string') throw new Error(`${label}: укажите текстовое имя.`);
    const name = value.normalize('NFC').trim();
    if (!name || name === '.' || name === '..') throw new Error(`${label}: имя не может быть пустым или служебным.`);
    if (name.length > 180) throw new Error(`${label}: максимум 180 символов.`);
    if (/[\\/\u0000-\u001f\u007f]/.test(name)) throw new Error(`${label}: символы / и \\ не допускаются.`);
    return name;
}

export function driveItemKey(item) {
    return isFolderRecord(item) ? `folder:${item.id}` : `file:${item.cid}`;
}

export function getDriveChildren(items, parentId = null) {
    return items.filter(item => (item.parentId || null) === (parentId || null));
}

export function getDriveFolderPath(items, folderId) {
    if (!folderId) return [];
    const byId = new Map(items.filter(isFolderRecord).map(folder => [folder.id, folder]));
    const path = [];
    const seen = new Set();
    let current = byId.get(folderId);
    while (current) {
        if (seen.has(current.id)) throw new Error('Обнаружен цикл в структуре папок.');
        seen.add(current.id);
        path.unshift(current);
        if (current.parentId && !byId.has(current.parentId)) throw new Error('Родительская папка не найдена.');
        current = current.parentId ? byId.get(current.parentId) : null;
    }
    if (path[0]?.id !== folderId && !path.some(folder => folder.id === folderId)) {
        throw new Error('Папка не найдена.');
    }
    return path;
}

export function getDescendantFolderIds(items, folderId) {
    const result = new Set([folderId]);
    let changed = true;
    while (changed) {
        changed = false;
        for (const item of items) {
            if (isFolderRecord(item) && item.parentId && result.has(item.parentId) && !result.has(item.id)) {
                result.add(item.id);
                changed = true;
            }
        }
    }
    return result;
}

export function collectFolderContents(items, folderId) {
    const folderIds = getDescendantFolderIds(items, folderId);
    return {
        folderIds,
        folders: items.filter(item => isFolderRecord(item) && folderIds.has(item.id)),
        files: items.filter(item => !isFolderRecord(item) && item.cid && folderIds.has(item.parentId)),
    };
}

export function canMoveFolder(items, folderId, targetParentId) {
    if (!targetParentId) return true;
    if (folderId === targetParentId) return false;
    return !getDescendantFolderIds(items, folderId).has(targetParentId);
}

export function getRelativePath(items, folderId, file) {
    const folderPath = getDriveFolderPath(items, folderId).map(folder => folder.name);
    const filePath = getDriveFolderPath(items, file.parentId).map(folder => folder.name);
    const relative = filePath.slice(folderPath.length);
    return [...relative, file.name].join('/');
}

export function getRelativeFolderPath(items, rootFolderId, childFolderId) {
    const rootPath = getDriveFolderPath(items, rootFolderId);
    const childPath = getDriveFolderPath(items, childFolderId);
    if (childPath.length < rootPath.length || rootPath.some((folder, index) => childPath[index]?.id !== folder.id)) {
        throw new Error('Папка не находится внутри выбранной папки.');
    }
    return childPath.slice(rootPath.length).map(folder => folder.name).join('/');
}

export function isSafeArchivePath(path) {
    if (typeof path !== 'string' || !path || path.length > 4096) return false;
    if (path.startsWith('/') || path.startsWith('\\') || /^[a-zA-Z]:/.test(path)) return false;
    const segments = path.replace(/\\/g, '/').split('/');
    return segments.every(segment => segment !== '..' && segment !== '.' && !segment.includes('\0'));
}

export function listArchiveChildren(entries, currentPath = '') {
    const prefix = currentPath ? `${currentPath.replace(/\/$/, '')}/` : '';
    const children = new Map();
    for (const entry of entries) {
        const rawName = String(entry.unsafeOriginalName || entry.name || '');
        const isDir = Boolean(entry.dir);
        const normalized = rawName.replace(/\\/g, '/').replace(/^\/+/, '');
        if (!isSafeArchivePath(normalized)) continue;
        if (!normalized.startsWith(prefix)) continue;
        const remainder = normalized.slice(prefix.length);
        if (!remainder) continue;
        const slash = remainder.indexOf('/');
        if (slash >= 0) {
            const folderName = remainder.slice(0, slash);
            if (folderName) children.set(`d:${folderName}`, { name: folderName, dir: true, path: `${prefix}${folderName}/` });
        } else if (isDir) {
            const folderName = remainder.replace(/\/$/, '');
            if (folderName) children.set(`d:${folderName}`, { name: folderName, dir: true, path: `${prefix}${folderName}/` });
        } else {
            children.set(`f:${remainder}`, { name: remainder, dir: false, path: normalized, entry });
        }
    }
    return [...children.values()].sort((a, b) => Number(b.dir) - Number(a.dir) || a.name.localeCompare(b.name, 'ru', { sensitivity: 'base' }));
}

export function buildFolderUploadPlan(rootNameInput, parentId, fileEntries, directoryPaths = []) {
    const rootName = normalizeDriveName(rootNameInput, 'Папка');
    const dirs = new Set(['']);
    for (const path of directoryPaths) {
        const normalized = String(path || '').replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
        if (!normalized) continue;
        if (!isSafeArchivePath(normalized)) throw new Error('Путь папки содержит недопустимые сегменты.');
        const parts = normalized.split('/');
        let built = '';
        for (const part of parts) {
            const safe = normalizeDriveName(part, 'Имя вложенной папки');
            built = built ? `${built}/${safe}` : safe;
            dirs.add(built);
        }
    }
    const files = fileEntries.map(item => {
        const relativePath = String(item.relativePath || item.file?.name || '').replace(/\\/g, '/').replace(/^\/+/, '');
        if (!isSafeArchivePath(relativePath) || relativePath.endsWith('/')) throw new Error('Путь файла содержит недопустимые сегменты.');
        const parts = relativePath.split('/');
        const fileName = normalizeDriveName(parts.pop(), 'Имя файла');
        let built = '';
        for (const part of parts) {
            const safe = normalizeDriveName(part, 'Имя вложенной папки');
            built = built ? `${built}/${safe}` : safe;
            dirs.add(built);
        }
        return { file: item.file, relativeDir: built, name: fileName };
    });
    return { rootName, parentId: parentId || null, directories: [...dirs].filter(Boolean).sort((a, b) => a.split('/').length - b.split('/').length || a.localeCompare(b, 'ru')), files };
}

export function buildIncomingFolderMergePlan(items, incomingFolders, deletedFolderIds = []) {
    const deleted = new Set(deletedFolderIds);
    const folderMap = new Map();
    for (const folder of items.filter(isFolderRecord)) {
        if (typeof folder.id === 'string' && folder.id && !deleted.has(folder.id)) folderMap.set(folder.id, folder);
    }
    const byId = new Map();
    for (const folder of incomingFolders) {
        if (typeof folder?.id === 'string' && folder.id && !deleted.has(folder.id)) byId.set(folder.id, folder);
    }
    for (const [id, folder] of byId) folderMap.set(id, folder);

    const candidates = [];
    const depthById = new Map();
    for (const original of byId.values()) {
        if (original.parentId != null && typeof original.parentId !== 'string') continue;
        let name;
        try { name = normalizeDriveName(original.name, 'Имя папки'); } catch (_) { continue; }
        let parentId = original.parentId || null;
        const seen = new Set([original.id]);
        let depth = 0;
        let valid = true;
        while (parentId) {
            if (seen.has(parentId) || deleted.has(parentId)) { valid = false; break; }
            seen.add(parentId);
            const parent = folderMap.get(parentId);
            if (!parent || !isFolderRecord(parent)) { valid = false; break; }
            parentId = parent.parentId || null;
            depth++;
            if (depth > 1024) { valid = false; break; }
        }
        if (!valid) continue;
        depthById.set(original.id, depth);
        candidates.push({ ...original, type: 'folder', name, parentId: original.parentId || null });
    }

    candidates.sort((a, b) => (depthById.get(a.id) || 0) - (depthById.get(b.id) || 0) || a.id.localeCompare(b.id));
    const availableIds = new Set(items.filter(item => isFolderRecord(item) && !deleted.has(item.id)).map(item => item.id));
    const accepted = [];

    for (const folder of candidates) {
        if (folder.parentId && !availableIds.has(folder.parentId)) continue;
        const normalizedName = folder.name.toLocaleLowerCase('ru');
        const conflict = items.some(item => item.id !== folder.id &&
            (item.parentId || null) === folder.parentId &&
            String(item.name || '').toLocaleLowerCase('ru') === normalizedName) ||
            accepted.some(item => (item.parentId || null) === folder.parentId && item.name.toLocaleLowerCase('ru') === normalizedName);
        if (conflict) continue;
        accepted.push(folder);
        availableIds.add(folder.id);
    }
    return accepted;
}

