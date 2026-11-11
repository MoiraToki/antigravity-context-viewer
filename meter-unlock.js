'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const PCLNTAB_MAGIC = 0xFFFFFFF1;

const FUNC_OFFERS = 'model.SelectorModel.offersContextWindow';
const FUNC_STORE_CW = 'store.(*Store).ContextWindow';
const FUNC_STORE_CHOICE = 'store.(*Store).ContextWindowChoice';
const FUNC_CHECKPOINT = 'utils.GetCheckpointConfig';
const FUNC_EXP_CHECKPOINT = 'config.applyFeatureProviderCheckpointOverrideConfig';
const FUNC_SELECT_EXP_KEY = 'config.selectCheckpointExperimentKey';

const REQUIRED_SERVER_SYMBOLS = [
  FUNC_CHECKPOINT,
  FUNC_EXP_CHECKPOINT,
  FUNC_SELECT_EXP_KEY
];

const PATCH_UNLIMITED_X64 = Buffer.from('89d6' + '90'.repeat(12), 'hex');

const PRESET_MODES = {
  '256k': { mode: '256k', capTokens: 256000, label: '256K (默认)' },
  '512k': { mode: '512k', capTokens: 512000, label: '512K (v4 推荐)' },
  '1m': { mode: '1m', capTokens: 1000000, label: '1M (1000K)' },
  unlimited: { mode: 'unlimited', capTokens: null, label: '取消本地封顶 (v3)' }
};

const MIN_CUSTOM_CAP_TOKENS = 64000;
const MAX_CUSTOM_CAP_TOKENS = 4096000;

class PatchError extends Error {
  constructor(message, code = 'PATCH_ERROR') {
    super(message);
    this.name = 'PatchError';
    this.code = code;
  }
}

function sha256Buffer(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function sha256FileSync(filePath, fsImpl = fs) {
  return sha256Buffer(fsImpl.readFileSync(filePath));
}

function sleepAsync(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function normalizeTargetPathKey(targetPath) {
  return path.resolve(String(targetPath || '')).toLowerCase();
}

function computeTargetId(targetPath) {
  return crypto.createHash('sha256').update(normalizeTargetPathKey(targetPath)).digest('hex').slice(0, 12);
}

/**
 * 4.1 无副作用的状态目录路径计算函数（不执行 mkdirSync）
 */
function resolveUnlockStateDir(options = {}) {
  if (options && typeof options._testStateDir === 'string' && options._testStateDir.trim()) {
    return path.resolve(options._testStateDir.trim());
  }
  const home = os.homedir();
  const base = process.platform === 'win32'
    ? (process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local'))
    : process.platform === 'darwin'
      ? path.join(home, 'Library', 'Application Support')
      : (process.env.XDG_STATE_HOME || path.join(home, '.local', 'state'));
  return path.join(base, 'AntigravityContextMeter');
}

function getTargetArtifactPaths(targetPath, options = {}) {
  const stateDir = resolveUnlockStateDir(options);
  const targetId = computeTargetId(targetPath);
  return {
    stateDir,
    targetId,
    lockDir: path.join(stateDir, `unlock-${targetId}.lock.d`),
    txPath: path.join(stateDir, `unlock-tx-${targetId}.json`),
    manifestPath: path.join(stateDir, `unlock-manifest-${targetId}.json`),
    backupsDir: path.join(stateDir, 'backups')
  };
}

function classifyCapTokens(capTokens) {
  if (capTokens === null || capTokens === undefined) {
    return { mode: 'unlimited', capTokens: null, label: PRESET_MODES.unlimited.label };
  }
  const n = Number(capTokens);
  if (n === 256000) return { ...PRESET_MODES['256k'] };
  if (n === 512000) return { ...PRESET_MODES['512k'] };
  if (n === 1000000) return { ...PRESET_MODES['1m'] };
  const k = Math.round(n / 1000);
  return {
    mode: 'custom',
    capTokens: n,
    label: `${k}K (自定义)`
  };
}

function normalizeTargetSpec(input = {}) {
  const src = (input && input.mode == null && input.tier == null && input.target && typeof input.target === 'object')
    ? input.target
    : (input || {});
  const rawMode = String(src.mode || src.tier || '512k').trim().toLowerCase();
  if (rawMode === '256k' || rawMode === 'default' || rawMode === '256000') {
    return { ...PRESET_MODES['256k'] };
  }
  if (rawMode === '512k' || rawMode === '512000') {
    return { ...PRESET_MODES['512k'] };
  }
  if (rawMode === '1m' || rawMode === '1000k' || rawMode === '1000000') {
    return { ...PRESET_MODES['1m'] };
  }
  if (rawMode === 'unlimited' || rawMode === 'uncapped' || rawMode === 'v3') {
    return { ...PRESET_MODES.unlimited };
  }
  let capTokens = null;
  if (rawMode === 'custom') {
    if (src.capTokens != null) {
      capTokens = Number(src.capTokens);
    } else if (src.customCapTokens != null) {
      capTokens = Number(src.customCapTokens);
    } else if (src.customK != null) {
      capTokens = Number(src.customK) * 1000;
    }
  } else {
    const mK = rawMode.match(/^(\d+)k$/i);
    if (mK) {
      capTokens = Number(mK[1]) * 1000;
    } else if (/^\d+$/.test(rawMode)) {
      const val = Number(rawMode);
      capTokens = val <= 4096 ? val * 1000 : val;
    }
  }
  if (!Number.isInteger(capTokens) || capTokens < MIN_CUSTOM_CAP_TOKENS || capTokens > MAX_CUSTOM_CAP_TOKENS || capTokens % 1000 !== 0) {
    throw new PatchError(
      `无效的自定义容量档位：需为 ${MIN_CUSTOM_CAP_TOKENS / 1000}K ~ ${MAX_CUSTOM_CAP_TOKENS / 1000}K 之间的整数千位（1K = 1,000 tokens）`,
      'INVALID_TIER_SPEC'
    );
  }
  return classifyCapTokens(capTokens);
}

/**
 * 清洗来自 IPC / HTTP 桥接层的外部参数，严格白名单过滤，阻断覆盖内部测试与运行时钩子
 */
function sanitizePublicUnlockOptions(rawInput = {}, fixedOverrides = {}) {
  const raw = (rawInput && typeof rawInput === 'object') ? rawInput : {};
  const specSrc = (raw.mode == null && raw.tier == null && raw.target && typeof raw.target === 'object')
    ? raw.target
    : raw;
  const clean = {};
  if (specSrc.mode !== undefined) clean.mode = specSrc.mode;
  if (specSrc.tier !== undefined) clean.tier = specSrc.tier;
  if (specSrc.capTokens !== undefined) clean.capTokens = specSrc.capTokens;
  if (specSrc.customCapTokens !== undefined) clean.customCapTokens = specSrc.customCapTokens;
  if (specSrc.customK !== undefined) clean.customK = specSrc.customK;
  if (raw.force === true) clean.force = true;
  if (typeof raw.expectedBeforeSha256 === 'string' && raw.expectedBeforeSha256.trim()) {
    clean.expectedBeforeSha256 = raw.expectedBeforeSha256.trim();
  }
  if (raw.expectedInstanceIdentity && typeof raw.expectedInstanceIdentity === 'object') {
    const id = raw.expectedInstanceIdentity;
    clean.expectedInstanceIdentity = {
      pid: Number.isInteger(Number(id.pid)) ? Number(id.pid) : undefined,
      creationDate: typeof id.creationDate === 'string' ? id.creationDate : ''
    };
  }
  return { ...clean, ...fixedOverrides };
}

function encodeGate3aBytesX64(spec) {
  if (spec.mode === 'unlimited') {
    return Buffer.from(PATCH_UNLIMITED_X64);
  }
  const cap = Number(spec.capTokens);
  if (!Number.isInteger(cap) || cap <= 0 || cap > 0x7FFFFFFF) {
    throw new PatchError(`Invalid Gate 3A token cap: ${cap}`, 'INVALID_TIER_SPEC');
  }
  const buf = Buffer.alloc(14);
  buf[0] = 0x81;
  buf[1] = 0xFA;
  buf.writeUInt32LE(cap, 2);
  buf[6] = 0xBE;
  buf.writeUInt32LE(cap, 7);
  buf[11] = 0x0F;
  buf[12] = 0x42;
  buf[13] = 0xF2;
  return buf;
}

// ============================================================================
// 2.1 PE32+ & Go .gopclntab / runtime.moduledata 解析
// ============================================================================

function parsePeLayout(data) {
  if (!Buffer.isBuffer(data) || data.length < 0x40) {
    throw new PatchError('truncated DOS header', 'INVALID_PE');
  }
  if (data[0] !== 0x4D || data[1] !== 0x5A) {
    throw new PatchError('unrecognised binary container (expected PE MZ header)', 'INVALID_PE');
  }
  const pe = data.readUInt32LE(0x3C);
  if (pe + 24 > data.length || data[pe] !== 0x50 || data[pe + 1] !== 0x45 || data[pe + 2] !== 0x00 || data[pe + 3] !== 0x00) {
    throw new PatchError('invalid PE header signature', 'INVALID_PE');
  }
  const machine = data.readUInt16LE(pe + 4);
  const arch = machine === 0x8664 ? 'x86-64' : (machine === 0xAA64 ? 'arm64' : null);
  if (!arch) {
    throw new PatchError(`unsupported PE machine 0x${machine.toString(16)}`, 'UNSUPPORTED_ARCH');
  }
  const nsec = data.readUInt16LE(pe + 6);
  const optSize = data.readUInt16LE(pe + 20);
  const opt = pe + 24;
  if (optSize < 112 || opt + optSize > data.length) {
    throw new PatchError('truncated PE optional header', 'INVALID_PE');
  }
  if (data.readUInt16LE(opt) !== 0x20B) {
    throw new PatchError('only PE32+ (64-bit) executables are supported', 'INVALID_PE');
  }
  const imageBaseBig = data.readBigUInt64LE(opt + 24);
  const imageBase = Number(imageBaseBig);
  const sect = opt + optSize;
  if (sect + nsec * 40 > data.length) {
    throw new PatchError('truncated PE section table', 'INVALID_PE');
  }
  const sections = [];
  for (let i = 0; i < nsec; i++) {
    const off = sect + i * 40;
    let nameEnd = off;
    while (nameEnd < off + 8 && data[nameEnd] !== 0) nameEnd++;
    const name = data.subarray(off, nameEnd).toString('latin1');
    const vsize = data.readUInt32LE(off + 8);
    const vaddr = data.readUInt32LE(off + 12);
    const rawsize = data.readUInt32LE(off + 16);
    const rawptr = data.readUInt32LE(off + 20);
    if (rawsize && rawptr + rawsize > data.length) {
      throw new PatchError(`truncated PE section ${name}`, 'INVALID_PE');
    }
    sections.push({ name, vaddr, rawptr, rawsize, vsize });
  }
  return { imageBase, imageBaseBig, arch, sections };
}

function findTextSection(data) {
  const { imageBase, arch, sections } = parsePeLayout(data);
  for (const s of sections) {
    if (s.name === '.text' && s.rawsize > 0) {
      return { textVa: imageBase + s.vaddr, textOff: s.rawptr, arch };
    }
  }
  throw new PatchError('.text section not found in PE', 'INVALID_PE');
}

function fileOffsetToVa(data, offset, layout = null) {
  const { imageBase, sections } = layout || parsePeLayout(data);
  for (const s of sections) {
    if (offset >= s.rawptr && offset < s.rawptr + s.rawsize) {
      return imageBase + s.vaddr + (offset - s.rawptr);
    }
  }
  throw new PatchError(`file offset 0x${offset.toString(16)} is not in a PE section`, 'INVALID_PE');
}

function findPclntab(data) {
  const magic = Buffer.alloc(6);
  magic.writeUInt32LE(PCLNTAB_MAGIC, 0);
  magic[4] = 0;
  magic[5] = 0;

  let pos = 0;
  while (true) {
    const i = data.indexOf(magic, pos);
    if (i < 0) {
      throw new PatchError('Go pclntab not found', 'PCLNTAB_NOT_FOUND');
    }
    pos = i + 1;
    if (i + 72 > data.length) continue;
    const minLC = data[i + 6];
    const ptrSize = data[i + 7];
    if ((minLC !== 1 && minLC !== 2 && minLC !== 4) || ptrSize !== 8) continue;
    const nfuncBig = data.readBigUInt64LE(i + 8);
    if (nfuncBig <= 1000n || nfuncBig >= 5000000n) continue;
    const nfunc = Number(nfuncBig);
    const fnOffBig = data.readBigUInt64LE(i + 32);
    if (fnOffBig > BigInt(data.length) || i + Number(fnOffBig) + 16 > data.length) continue;
    const fnOff = Number(fnOffBig);
    const head = data.subarray(i + fnOff, i + fnOff + 16);
    let validHead = head.length > 0;
    for (let k = 0; k < head.length; k++) {
      const c = head[k];
      if (!((c >= 0x20 && c < 0x7F) || c === 0)) {
        validHead = false;
        break;
      }
    }
    if (!validHead) continue;
    return { base: i, nfunc };
  }
}

function resolvePeGoText(data, layout = null, pclntab = null) {
  const peLayout = layout || parsePeLayout(data);
  const { imageBaseBig, sections } = peLayout;
  const { base, nfunc } = pclntab || findPclntab(data);
  const textVaBig = data.readBigUInt64LE(base + 24);

  function textLocation(vaBig) {
    for (const s of sections) {
      const secVaBig = imageBaseBig + BigInt(s.vaddr);
      const deltaBig = vaBig - secVaBig;
      if (s.name === '.text' && deltaBig >= 0n && deltaBig < BigInt(s.rawsize)) {
        const delta = Number(deltaBig);
        return {
          textVa: Number(vaBig),
          textOff: s.rawptr + delta,
          textEnd: s.rawptr + s.rawsize
        };
      }
    }
    throw new PatchError('Go textStart is outside the PE .text section', 'INVALID_GO_TEXT');
  }

  if (textVaBig !== 0n) {
    return textLocation(textVaBig);
  }

  const offsets = [];
  for (let i = 0; i < 5; i++) {
    const offBig = data.readBigUInt64LE(base + 32 + i * 8);
    if (offBig > BigInt(data.length)) {
      throw new PatchError('truncated Go pclntab offset', 'INVALID_GO_TEXT');
    }
    offsets.push(Number(offBig));
  }
  const tableVas = offsets.map(off => BigInt(fileOffsetToVa(data, base + off, peLayout)));
  const ftab = base + offsets[4];
  if (ftab + nfunc * 8 + 4 > data.length) {
    throw new PatchError('truncated Go function table', 'INVALID_GO_TEXT');
  }
  const first = BigInt(data.readUInt32LE(ftab));
  const last = BigInt(data.readUInt32LE(ftab + nfunc * 8));
  const needle = Buffer.alloc(8);
  needle.writeBigUInt64LE(BigInt(fileOffsetToVa(data, base, peLayout)), 0);

  const candidates = [];
  let pos = 0;
  while (true) {
    const site = data.indexOf(needle, pos);
    if (site < 0) break;
    pos = site + 1;
    if (site % 8 !== 0) continue;
    const inSection = sections.some(s => site >= s.rawptr && site + 192 <= s.rawptr + s.rawsize);
    if (!inSection) continue;

    const words = new Array(24);
    for (let w = 0; w < 24; w++) {
      words[w] = data.readBigUInt64LE(site + w * 8);
    }
    let tablesMatch = true;
    for (let i = 0; i < 5; i++) {
      if (words[1 + i * 3] !== tableVas[i] || words[2 + i * 3] !== words[3 + i * 3]) {
        tablesMatch = false;
        break;
      }
    }
    if (!tablesMatch) continue;
    const nfuncPlus1 = BigInt(nfunc + 1);
    if (words[16] !== tableVas[4] || words[17] !== nfuncPlus1 || words[18] !== nfuncPlus1) {
      continue;
    }
    const minpc = words[20];
    const maxpc = words[21];
    const text = words[22];
    const etext = words[23];
    if (!(minpc === text + first && maxpc === text + last && text <= minpc && minpc < maxpc && maxpc <= etext)) {
      continue;
    }
    let location;
    try {
      location = textLocation(text);
    } catch {
      continue;
    }
    if (Number(etext - text) > location.textEnd - location.textOff) {
      continue;
    }
    candidates.push(location);
  }

  if (candidates.length !== 1) {
    throw new PatchError(
      `Go textStart is zero: expected one validated PE moduledata, found ${candidates.length}`,
      'AMBIGUOUS_MODULEDATA'
    );
  }
  return candidates[0];
}

function buildFunctions(data, pclntab = null) {
  const { base, nfunc } = pclntab || findPclntab(data);
  const fnstart = base + Number(data.readBigUInt64LE(base + 32));
  const pcln = base + Number(data.readBigUInt64LE(base + 64));

  const funcs = Object.create(null);
  for (let i = 0; i < nfunc; i++) {
    const off = pcln + i * 8;
    if (off + 16 > data.length) break;
    const entryoff = data.readUInt32LE(off);
    const funcoff = data.readUInt32LE(off + 4);
    const nextEntryoff = data.readUInt32LE(off + 8);
    const rec = pcln + funcoff;
    if (rec + 8 > data.length) continue;
    const nameoff = data.readInt32LE(rec + 4);
    const start = fnstart + nameoff;
    if (start < 0 || start >= data.length) continue;
    const maxEnd = Math.min(data.length, start + 1024);
    const end = data.indexOf(0x00, start);
    if (end < 0 || end >= maxEnd) continue;

    const slice = data.subarray(start, end);
    let isAscii = true;
    for (let k = 0; k < slice.length; k++) {
      if (slice[k] >= 0x80) {
        isAscii = false;
        break;
      }
    }
    if (!isAscii) continue;
    const fullName = slice.toString('latin1');
    const slashIdx = fullName.lastIndexOf('/');
    const shortName = slashIdx >= 0 ? fullName.slice(slashIdx + 1) : fullName;
    const size = Math.max(0, nextEntryoff - entryoff);

    if (!funcs[shortName]) {
      funcs[shortName] = {
        entryoff,
        size,
        fullName,
        count: 1,
        fullNames: [fullName]
      };
    } else {
      funcs[shortName].count += 1;
      if (funcs[shortName].fullNames.length < 5) {
        funcs[shortName].fullNames.push(fullName);
      }
    }
  }

  if (Object.keys(funcs).length === 0) {
    throw new PatchError('functab produced no symbols', 'EMPTY_FUNCTAB');
  }
  return funcs;
}

// ============================================================================
// 2.2 & 2.3 Gate 3A 与 Gate 3B 唯一性与完整性定位
// ============================================================================

function locateGate3a(body, fnVa, fnFileOff) {
  const hits = [];
  for (let rel = 0; rel <= body.length - 14; rel++) {
    if (
      body[rel] === 0x81 &&
      body[rel + 1] === 0xFA &&
      body[rel + 6] === 0xBE &&
      body[rel + 11] === 0x0F &&
      body[rel + 12] === 0x42 &&
      body[rel + 13] === 0xF2
    ) {
      const immA = body.readUInt32LE(rel + 2);
      const immB = body.readUInt32LE(rel + 7);
      if (immA === immB && immA > 0) {
        const info = classifyCapTokens(immA);
        hits.push({
          rel,
          fileOffset: fnFileOff + rel,
          va: fnVa + rel,
          mode: info.mode,
          capTokens: info.capTokens,
          label: info.label,
          rawBytesHex: body.subarray(rel, rel + 14).toString('hex')
        });
      }
    } else if (body.subarray(rel, rel + 14).equals(PATCH_UNLIMITED_X64)) {
      hits.push({
        rel,
        fileOffset: fnFileOff + rel,
        va: fnVa + rel,
        mode: 'unlimited',
        capTokens: null,
        label: PRESET_MODES.unlimited.label,
        rawBytesHex: body.subarray(rel, rel + 14).toString('hex')
      });
    }
  }

  if (hits.length === 0) {
    throw new PatchError(`${FUNC_CHECKPOINT}: x86-64 clamp pattern not found`, 'GATE3A_NOT_FOUND');
  }
  if (hits.length !== 1) {
    throw new PatchError(`${FUNC_CHECKPOINT}: multiple clamp candidates (${hits.length}); refusing to patch`, 'GATE3A_AMBIGUOUS');
  }
  return hits[0];
}

function locateGate3b(body, fnVa, fnFileOff, selectExpKeyVa, referenceOriginalGate3b = null) {
  const size = body.length;
  const candidates = [];

  for (let rel = 0; rel <= size - 5; rel++) {
    if (body[rel] !== 0xE8) continue;
    const disp = body.readInt32LE(rel + 1);
    if (fnVa + rel + 5 + disp !== selectExpKeyVa) continue;

    const winEnd = Math.min(size, rel + 105);
    for (let scan = rel + 5; scan <= winEnd - 2; scan++) {
      if (body[scan] === 0x84 && body[scan + 1] === 0xC0) {
        const jOff = scan + 2;
        if (jOff + 2 > size) {
          throw new PatchError(
            `${FUNC_EXP_CHECKPOINT}: truncated instruction after test %al,%al at end of function`,
            'GATE3B_TRUNCATED'
          );
        }
        candidates.push({ callRel: rel, testRel: scan, jOff });
      }
    }
  }

  if (candidates.length === 0) {
    throw new PatchError(`${FUNC_EXP_CHECKPOINT}: x86-64 override site not found`, 'GATE3B_NOT_FOUND');
  }
  if (candidates.length !== 1) {
    throw new PatchError(
      `${FUNC_EXP_CHECKPOINT}: multiple override candidates (${candidates.length}); refusing to patch`,
      'GATE3B_AMBIGUOUS'
    );
  }

  const { jOff } = candidates[0];

  if (referenceOriginalGate3b) {
    if (referenceOriginalGate3b.jOff !== jOff) {
      throw new PatchError(`${FUNC_EXP_CHECKPOINT}: Gate 3B offset mismatch with reference backup`, 'GATE3B_MISMATCH');
    }
    const origLen = referenceOriginalGate3b.patchLen;
    if (jOff + origLen > size) {
      throw new PatchError(`${FUNC_EXP_CHECKPOINT}: Gate 3B truncated relative to reference backup`, 'GATE3B_TRUNCATED');
    }
    const origBytes = Buffer.from(referenceOriginalGate3b.originalBytesHex, 'hex');
    const curSlice = body.subarray(jOff, jOff + origLen);
    if (curSlice.equals(origBytes)) {
      return {
        jOff,
        fileOffset: fnFileOff + jOff,
        va: fnVa + jOff,
        state: 'UNPATCHED',
        patched: false,
        patchLen: origLen,
        jumpKind: referenceOriginalGate3b.jumpKind,
        targetRel: referenceOriginalGate3b.targetRel,
        originalBytesHex: referenceOriginalGate3b.originalBytesHex
      };
    }
    if (curSlice.equals(Buffer.alloc(origLen, 0x90))) {
      return {
        jOff,
        fileOffset: fnFileOff + jOff,
        va: fnVa + jOff,
        state: 'VERIFIED_PATCHED',
        patched: true,
        patchLen: origLen,
        jumpKind: referenceOriginalGate3b.jumpKind,
        targetRel: referenceOriginalGate3b.targetRel,
        originalBytesHex: referenceOriginalGate3b.originalBytesHex
      };
    }
    throw new PatchError(
      `${FUNC_EXP_CHECKPOINT}: Gate 3B site is partially overwritten or corrupted`,
      'CORRUPTED_GATE3B'
    );
  }

  // 无参考备份的静态解析
  const b0 = body[jOff];
  const b1 = body[jOff + 1];

  if (b0 === 0x75) {
    const rel8 = body.readInt8(jOff + 1);
    const targetRel = jOff + 2 + rel8;
    if (targetRel < 0 || targetRel >= size || targetRel === jOff + 2) {
      throw new PatchError(`${FUNC_EXP_CHECKPOINT}: jne rel8 target out of function bounds`, 'GATE3B_INVALID_TARGET');
    }
    return {
      jOff,
      fileOffset: fnFileOff + jOff,
      va: fnVa + jOff,
      state: 'UNPATCHED',
      patched: false,
      patchLen: 2,
      jumpKind: 'jne_rel8',
      targetRel,
      originalBytesHex: body.subarray(jOff, jOff + 2).toString('hex')
    };
  }

  if (b0 === 0x0F && b1 === 0x85) {
    if (jOff + 6 > size) {
      throw new PatchError(`${FUNC_EXP_CHECKPOINT}: truncated jne rel32 at end of function`, 'GATE3B_TRUNCATED');
    }
    const rel32 = body.readInt32LE(jOff + 2);
    const targetRel = jOff + 6 + rel32;
    if (targetRel < 0 || targetRel >= size || targetRel === jOff + 6) {
      throw new PatchError(`${FUNC_EXP_CHECKPOINT}: jne rel32 target out of function bounds`, 'GATE3B_INVALID_TARGET');
    }
    return {
      jOff,
      fileOffset: fnFileOff + jOff,
      va: fnVa + jOff,
      state: 'UNPATCHED',
      patched: false,
      patchLen: 6,
      jumpKind: 'jne_rel32',
      targetRel,
      originalBytesHex: body.subarray(jOff, jOff + 6).toString('hex')
    };
  }

  if (b0 === 0x90 && b1 === 0x90) {
    return {
      jOff,
      fileOffset: fnFileOff + jOff,
      va: fnVa + jOff,
      state: 'UNVERIFIED_PATCHED',
      patched: true,
      patchLen: null,
      jumpKind: 'unknown_nop',
      targetRel: null,
      originalBytesHex: null
    };
  }

  if (b0 === 0x90) {
    throw new PatchError(`${FUNC_EXP_CHECKPOINT}: corrupted single-byte NOP at Gate 3B`, 'CORRUPTED_GATE3B');
  }

  throw new PatchError(
    `${FUNC_EXP_CHECKPOINT}: unrecognized instruction at Gate 3B site (0x${body.subarray(jOff, Math.min(size, jOff + 6)).toString('hex')})`,
    'GATE3B_UNKNOWN_INSTR'
  );
}

/**
 * 解析并校验 PE 二进制缓冲中的符号与 Gate 3A / Gate 3B 状态
 */
function inspectBinaryBuffer(buffer, options = {}) {
  try {
    if (!Buffer.isBuffer(buffer)) {
      throw new PatchError('Expected a Buffer', 'INVALID_BUFFER');
    }
    const layout = parsePeLayout(buffer);
    if (layout.arch !== 'x86-64') {
      throw new PatchError('Context Unlock requires a Windows x64 PE executable', 'UNSUPPORTED_ARCH');
    }
    const pclntab = findPclntab(buffer);
    const goText = resolvePeGoText(buffer, layout, pclntab);
    const funcs = buildFunctions(buffer, pclntab);

    for (const sym of REQUIRED_SERVER_SYMBOLS) {
      if (!funcs[sym]) {
        throw new PatchError(`symbol not found: ${sym}`, 'SYMBOL_NOT_FOUND');
      }
      if (funcs[sym].count > 1) {
        throw new PatchError(
          `ambiguous target symbol in pclntab: ${sym} (${funcs[sym].count} occurrences)`,
          'AMBIGUOUS_SYMBOL'
        );
      }
      const { entryoff, size } = funcs[sym];
      if (size <= 0 || goText.textOff + entryoff + size > goText.textEnd) {
        throw new PatchError(`invalid function range in PE .text: ${sym}`, 'INVALID_FUNC_RANGE');
      }
    }

    let refGate3b = options.referenceOriginalGate3b || null;
    if (!refGate3b && Buffer.isBuffer(options.verifiedOriginalBuf)) {
      const origRes = inspectBinaryBuffer(options.verifiedOriginalBuf);
      if (!origRes.ok) {
        throw new PatchError(`reference original binary invalid: ${origRes.error}`, origRes.code || 'INVALID_BACKUP');
      }
      if (origRes.gate3a.mode !== '256k' || origRes.gate3b.state !== 'UNPATCHED') {
        throw new PatchError('reference original binary is not in unpatched 256K state', 'INVALID_BACKUP');
      }
      refGate3b = origRes.gate3b;
    }

    const cpFn = funcs[FUNC_CHECKPOINT];
    const cpOff = goText.textOff + cpFn.entryoff;
    const cpVa = goText.textVa + cpFn.entryoff;
    const cpBody = buffer.subarray(cpOff, cpOff + cpFn.size);
    const gate3a = locateGate3a(cpBody, cpVa, cpOff);

    const expFn = funcs[FUNC_EXP_CHECKPOINT];
    const expOff = goText.textOff + expFn.entryoff;
    const expVa = goText.textVa + expFn.entryoff;
    const expBody = buffer.subarray(expOff, expOff + expFn.size);
    const selectVa = goText.textVa + funcs[FUNC_SELECT_EXP_KEY].entryoff;
    const gate3b = locateGate3b(expBody, expVa, expOff, selectVa, refGate3b);

    const isUnpatchedOriginal = gate3a.mode === '256k' && gate3b.state === 'UNPATCHED';
    const isUnverifiedExternal = gate3b.state === 'UNVERIFIED_PATCHED';
    const isMixedState =
      !isUnverifiedExternal &&
      ((gate3a.mode === '256k' && gate3b.patched === true) ||
       (gate3a.mode !== '256k' && gate3b.patched === false));

    let overallState = 'PATCHED';
    if (isUnpatchedOriginal) overallState = 'ORIGINAL_256K';
    else if (isUnverifiedExternal) overallState = 'UNVERIFIED_PATCHED';
    else if (isMixedState) overallState = 'MIXED_PATCHED';

    return {
      ok: true,
      arch: layout.arch,
      textVa: goText.textVa,
      textOff: goText.textOff,
      textEnd: goText.textEnd,
      symbolCount: pclntab.nfunc,
      overallState,
      isUnpatchedOriginal,
      isUnverifiedExternal,
      isMixedState,
      gate3a,
      gate3b,
      symbols: {
        [FUNC_CHECKPOINT]: { va: cpVa, size: cpFn.size, fullName: cpFn.fullName },
        [FUNC_EXP_CHECKPOINT]: { va: expVa, size: expFn.size, fullName: expFn.fullName },
        [FUNC_SELECT_EXP_KEY]: { va: selectVa, size: funcs[FUNC_SELECT_EXP_KEY].size, fullName: funcs[FUNC_SELECT_EXP_KEY].fullName }
      }
    };
  } catch (err) {
    return {
      ok: false,
      code: err.code || 'PATCH_ERROR',
      error: err.message || String(err)
    };
  }
}

/**
 * 3.2 同构建备份等价校验：除 Gate 3A (14B) 与 Gate 3B (2B/6B) 外，其余全文件所有字节必须 100% 相等
 */
function verifySameBuildBackup(currentBuf, backupBuf) {
  if (!Buffer.isBuffer(currentBuf) || !Buffer.isBuffer(backupBuf)) {
    return { valid: false, code: 'MISSING_BUFFER', reason: '缺少有效的二进制缓冲' };
  }
  if (currentBuf.length !== backupBuf.length) {
    return { valid: false, code: 'SIZE_MISMATCH', reason: '备份文件与当前文件大小不一致（非同一版本）' };
  }

  const bakInspect = inspectBinaryBuffer(backupBuf);
  if (!bakInspect.ok) {
    return { valid: false, code: bakInspect.code || 'INVALID_BACKUP', reason: `备份文件结构校验失败: ${bakInspect.error}` };
  }
  if (bakInspect.gate3a.mode !== '256k' || bakInspect.gate3b.state !== 'UNPATCHED') {
    return { valid: false, code: 'BACKUP_NOT_ORIGINAL', reason: '备份文件本身处于已修改状态，不是未修改的 256K 原版' };
  }

  const curInspect = inspectBinaryBuffer(currentBuf, { referenceOriginalGate3b: bakInspect.gate3b });
  if (!curInspect.ok) {
    return {
      valid: false,
      code: curInspect.code || 'CURRENT_CORRUPTED',
      reason: `当前文件靶点完整性校验失败: ${curInspect.error}`
    };
  }

  const spans = [
    { start: bakInspect.gate3a.fileOffset, end: bakInspect.gate3a.fileOffset + 14 },
    { start: bakInspect.gate3b.fileOffset, end: bakInspect.gate3b.fileOffset + bakInspect.gate3b.patchLen }
  ].sort((a, b) => a.start - b.start);

  let cursor = 0;
  for (const span of spans) {
    if (span.start > cursor) {
      if (Buffer.compare(currentBuf.subarray(cursor, span.start), backupBuf.subarray(cursor, span.start)) !== 0) {
        return {
          valid: false,
          code: 'NON_PATCH_BYTES_DIFFER',
          reason: '非补丁区字节存在差异：备份文件与当前二进制不属于同一客户端构建版本'
        };
      }
    }
    cursor = Math.max(cursor, span.end);
  }
  if (cursor < currentBuf.length) {
    if (Buffer.compare(currentBuf.subarray(cursor), backupBuf.subarray(cursor)) !== 0) {
      return {
        valid: false,
        code: 'NON_PATCH_BYTES_DIFFER',
        reason: '文件尾部字节存在差异：备份文件与当前二进制不属于同一客户端构建版本'
      };
    }
  }

  return {
    valid: true,
    backupInspect: bakInspect,
    currentInspect: curInspect
  };
}

/**
 * 基于已验证的原版基底 baseOriginalBuf 生成目标档位完整镜像
 */
function buildTargetImageFromOriginalBase(baseOriginalBuf, targetSpecInput, currentBufForComparison = null) {
  const spec = normalizeTargetSpec(targetSpecInput);
  const baseInspect = inspectBinaryBuffer(baseOriginalBuf);
  if (!baseInspect.ok) {
    throw new PatchError(`原版基底校验失败: ${baseInspect.error}`, baseInspect.code || 'INVALID_BASE');
  }
  if (baseInspect.gate3a.mode !== '256k' || baseInspect.gate3b.state !== 'UNPATCHED') {
    throw new PatchError('基底镜像不是未修改的 256K 原版状态', 'INVALID_BASE');
  }

  const targetBuf = Buffer.from(baseOriginalBuf);
  if (spec.mode !== '256k') {
    const gate3aBytes = encodeGate3aBytesX64(spec);
    gate3aBytes.copy(targetBuf, baseInspect.gate3a.fileOffset);
    const nopBytes = Buffer.alloc(baseInspect.gate3b.patchLen, 0x90);
    nopBytes.copy(targetBuf, baseInspect.gate3b.fileOffset);
  }

  const compareAgainst = Buffer.isBuffer(currentBufForComparison) ? currentBufForComparison : baseOriginalBuf;
  const beforeSha256 = sha256Buffer(compareAgainst);
  const afterSha256 = sha256Buffer(targetBuf);
  const changed = Buffer.compare(compareAgainst, targetBuf) !== 0;

  return {
    ok: true,
    spec,
    buffer: targetBuf,
    changed,
    beforeSha256,
    afterSha256,
    baseOriginalSha256: sha256Buffer(baseOriginalBuf),
    gate3a: {
      va: baseInspect.gate3a.va,
      fileOffset: baseInspect.gate3a.fileOffset,
      targetMode: spec.mode,
      targetCapTokens: spec.capTokens,
      targetLabel: spec.label
    },
    gate3b: {
      va: baseInspect.gate3b.va,
      fileOffset: baseInspect.gate3b.fileOffset,
      patchLen: baseInspect.gate3b.patchLen,
      jumpKind: baseInspect.gate3b.jumpKind,
      willBypass: spec.mode !== '256k'
    }
  };
}

// ============================================================================
// 3.3 原子 JSON 写入、严格事务日志读取与无竞态目录锁 (withUnlockLock)
// ============================================================================

function writeJsonAtomicSync(filePath, data, fsImpl = fs) {
  const resolved = path.resolve(filePath);
  const dir = path.dirname(resolved);
  fsImpl.mkdirSync(dir, { recursive: true });
  const serialized = JSON.stringify(data, null, 2) + '\n';
  const rand = crypto.randomBytes(4).toString('hex');
  const tmpPath = `${resolved}.tmp.${process.pid}.${Date.now()}.${rand}`;
  let fd = null;
  try {
    fd = fsImpl.openSync(tmpPath, 'w');
    fsImpl.writeSync(fd, serialized, 0, 'utf8');
    fsImpl.fsyncSync(fd);
    fsImpl.closeSync(fd);
    fd = null;
    const checkRaw = fsImpl.readFileSync(tmpPath, 'utf8');
    JSON.parse(checkRaw);
    fsImpl.renameSync(tmpPath, resolved);
  } catch (err) {
    if (fd !== null) {
      try { fsImpl.closeSync(fd); } catch {}
    }
    try {
      if (fsImpl.existsSync(tmpPath)) fsImpl.unlinkSync(tmpPath);
    } catch {}
    throw err;
  }
}

function readTxLogStrict(txPath, fsImpl = fs) {
  const resolved = path.resolve(txPath);
  if (!fsImpl.existsSync(resolved)) {
    return { state: 'NONE', tx: null, txPath: resolved };
  }
  try {
    const raw = fsImpl.readFileSync(resolved, 'utf8');
    if (!raw || !raw.trim()) {
      return { state: 'CORRUPTED', tx: null, txPath: resolved, error: '事务日志文件为空' };
    }
    const parsed = JSON.parse(raw);
    if (
      !parsed ||
      typeof parsed !== 'object' ||
      typeof parsed.txId !== 'string' ||
      typeof parsed.targetId !== 'string' ||
      typeof parsed.targetPath !== 'string' ||
      typeof parsed.status !== 'string'
    ) {
      return { state: 'CORRUPTED', tx: null, txPath: resolved, error: '事务日志缺少必需字段' };
    }
    return { state: 'OK', tx: parsed, txPath: resolved };
  } catch (err) {
    return {
      state: 'CORRUPTED',
      tx: null,
      txPath: resolved,
      error: `事务日志解析失败: ${err.message}`
    };
  }
}

function isProcessAliveDefault(pid) {
  const numPid = Number(pid);
  if (!Number.isInteger(numPid) || numPid <= 0) return false;
  if (numPid === process.pid) return true;
  try {
    process.kill(numPid, 0);
    return true;
  } catch (err) {
    if (err && err.code === 'EPERM') return true;
    return false;
  }
}

function cleanupDirSafeSync(dirPath, fsImpl = fs) {
  try {
    if (!fsImpl.existsSync(dirPath)) return;
    const entries = fsImpl.readdirSync(dirPath);
    for (const entry of entries) {
      try { fsImpl.unlinkSync(path.join(dirPath, entry)); } catch {}
    }
    fsImpl.rmdirSync(dirPath);
  } catch {}
}

function createPopulatedDirSync(dirPath, fileName, jsonObj, fsImpl = fs) {
  fsImpl.mkdirSync(dirPath, { recursive: true });
  const filePath = path.join(dirPath, fileName);
  const serialized = JSON.stringify(jsonObj, null, 2) + '\n';
  const fd = fsImpl.openSync(filePath, 'w');
  try {
    fsImpl.writeSync(fd, serialized, 0, 'utf8');
    fsImpl.fsyncSync(fd);
  } finally {
    fsImpl.closeSync(fd);
  }
}

/**
 * 3.3.2 跨进程目录锁与陈旧锁无竞态门禁回收协议
 */
async function withUnlockLock(targetPath, fn, options = {}) {
  const fsImpl = options.fs || fs;
  const isProcessAlive = options.isProcessAlive || isProcessAliveDefault;
  const { stateDir, targetId, lockDir } = getTargetArtifactPaths(targetPath, options);
  fsImpl.mkdirSync(stateDir, { recursive: true });

  const myToken = options._testOwnerToken || crypto.randomUUID();
  const maxAcquireAttempts = 3;
  let acquired = false;

  for (let attempt = 1; attempt <= maxAcquireAttempts; attempt++) {
    const prepDir = path.join(stateDir, `unlock-${targetId}.prep-${process.pid}-${myToken}-${attempt}.d`);
    createPopulatedDirSync(prepDir, 'owner.json', {
      pid: process.pid,
      token: myToken,
      targetId,
      targetPath: path.resolve(targetPath),
      createdAt: Date.now()
    }, fsImpl);

    if (typeof options._onAfterPrepLockCreated === 'function') {
      await options._onAfterPrepLockCreated({ prepDir, lockDir, myToken, attempt });
    }

    try {
      fsImpl.renameSync(prepDir, lockDir);
      acquired = true;
      break;
    } catch {
      // lockDir 可能已存在，尝试读取 owner.json
      const ownerPath = path.join(lockDir, 'owner.json');
      let staleOwner = null;
      try {
        const raw = fsImpl.readFileSync(ownerPath, 'utf8');
        staleOwner = JSON.parse(raw);
      } catch (readErr) {
        if (readErr && readErr.code === 'ENOENT') {
          if (!fsImpl.existsSync(lockDir)) {
            cleanupDirSafeSync(prepDir, fsImpl);
            if (attempt < maxAcquireAttempts) {
              continue;
            }
            return {
              ok: false,
              code: 'LOCK_CONTENTION_RETRY_EXHAUSTED',
              error: '锁状态发生变化，请重试'
            };
          }
          // 再次重读 owner.json，区分“旧锁释放后新进程取得”、“刚刚释放消失”与“锁目录确实缺失/损坏”
          await sleepAsync(10);
          if (!fsImpl.existsSync(lockDir)) {
            cleanupDirSafeSync(prepDir, fsImpl);
            if (attempt < maxAcquireAttempts) continue;
            return {
              ok: false,
              code: 'LOCK_CONTENTION_RETRY_EXHAUSTED',
              error: '锁状态发生变化，请重试'
            };
          }
          try {
            const retryRaw = fsImpl.readFileSync(ownerPath, 'utf8');
            staleOwner = JSON.parse(retryRaw);
          } catch (retryErr) {
            cleanupDirSafeSync(prepDir, fsImpl);
            if (retryErr && retryErr.code === 'ENOENT' && !fsImpl.existsSync(lockDir)) {
              if (attempt < maxAcquireAttempts) continue;
              return {
                ok: false,
                code: 'LOCK_CONTENTION_RETRY_EXHAUSTED',
                error: '锁状态发生变化，请重试'
              };
            }
            return {
              ok: false,
              code: 'CORRUPTED_LOCK_FILE',
              lockDir,
              error: '锁目录元数据缺失或已损坏，已保留现场并中止操作'
            };
          }
        } else {
          cleanupDirSafeSync(prepDir, fsImpl);
          return {
            ok: false,
            code: 'CORRUPTED_LOCK_FILE',
            lockDir,
            error: '锁目录元数据缺失或已损坏，已保留现场并中止操作'
          };
        }
      }

      if (
        !staleOwner ||
        typeof staleOwner !== 'object' ||
        !Number.isInteger(Number(staleOwner.pid)) ||
        typeof staleOwner.token !== 'string' ||
        !staleOwner.token
      ) {
        cleanupDirSafeSync(prepDir, fsImpl);
        return {
          ok: false,
          code: 'CORRUPTED_LOCK_FILE',
          lockDir,
          error: '锁目录元数据字段非法，已保留现场并中止操作'
        };
      }

      if (isProcessAlive(staleOwner.pid)) {
        cleanupDirSafeSync(prepDir, fsImpl);
        return {
          ok: false,
          code: 'LOCKED_BY_OTHER_PROCESS',
          ownerPid: staleOwner.pid,
          error: `另一个进程 (PID ${staleOwner.pid}) 正在修改该二进制文件，请稍后重试`
        };
      }

      // 所有者已确认退出 (ESRCH)：构造绑定 staleOwner.token 的门禁目录
      if (typeof options._onBeforeReclaimGate === 'function') {
        await options._onBeforeReclaimGate({ staleOwner, lockDir, prepDir, myToken });
      }

      const gateDir = path.join(stateDir, `unlock-${targetId}.reclaim-${staleOwner.token}.gate.d`);
      const prepGateDir = path.join(stateDir, `unlock-${targetId}.prepgate-${process.pid}-${myToken}.d`);
      const initialReclaimer = {
        status: 'RECLAIMING',
        reclaimerPid: process.pid,
        reclaimerToken: myToken,
        staleToken: staleOwner.token,
        createdAt: Date.now()
      };
      createPopulatedDirSync(prepGateDir, 'reclaimer.json', initialReclaimer, fsImpl);

      let wonGate = false;
      try {
        fsImpl.renameSync(prepGateDir, gateDir);
        wonGate = true;
      } catch (gateErr) {
        cleanupDirSafeSync(prepGateDir, fsImpl);
        cleanupDirSafeSync(prepDir, fsImpl);

        if (!fsImpl.existsSync(gateDir)) {
          return {
            ok: false,
            code: 'RECLAIM_GATE_CREATE_ERROR',
            error: `创建陈旧锁回收门禁失败: ${gateErr.message}`
          };
        }

        // 分支 A：gateDir 已存在，读取 reclaimer.json 与当前 lockDir/owner.json
        let curLockOwner = null;
        try {
          if (fsImpl.existsSync(lockDir)) {
            curLockOwner = JSON.parse(fsImpl.readFileSync(ownerPath, 'utf8'));
          }
        } catch {}

        let reclaimerMeta = null;
        let reclaimerCorrupted = false;
        try {
          reclaimerMeta = JSON.parse(fsImpl.readFileSync(path.join(gateDir, 'reclaimer.json'), 'utf8'));
          if (!reclaimerMeta || typeof reclaimerMeta.status !== 'string' || !reclaimerMeta.reclaimerPid) {
            reclaimerCorrupted = true;
          }
        } catch {
          reclaimerCorrupted = true;
        }

        if (reclaimerMeta && reclaimerMeta.status === 'FAILED') {
          return {
            ok: false,
            code: 'RECLAIM_FAILED_MANUAL_INTERVENTION_REQUIRED',
            lockDir,
            gateDir,
            error: '前次陈旧锁回收移锁失败：请先停止相关操作，仅核对并处理锁目录与门禁目录，保留 unlock-tx-*.json 及 .old、.bak 恢复材料'
          };
        }

        if (!curLockOwner || curLockOwner.token !== staleOwner.token || (reclaimerMeta && (reclaimerMeta.status === 'OLD_LOCK_RETIRED' || reclaimerMeta.status === 'COMPLETED'))) {
          return {
            ok: false,
            code: 'LOCKED_BY_OTHER_PROCESS',
            error: '另一个进程正在回收或持有该目标锁，请稍后重试'
          };
        }

        if (!reclaimerCorrupted && reclaimerMeta.status === 'RECLAIMING' && isProcessAlive(reclaimerMeta.reclaimerPid)) {
          return {
            ok: false,
            code: 'LOCKED_BY_OTHER_PROCESS',
            ownerPid: reclaimerMeta.reclaimerPid,
            error: `另一个进程 (PID ${reclaimerMeta.reclaimerPid}) 正在回收陈旧锁，请稍后重试`
          };
        }

        return {
          ok: false,
          code: 'RECLAIM_INTERRUPTED',
          lockDir,
          gateDir,
          staleToken: staleOwner.token,
          error: '陈旧锁自动回收异常中断：请先停止针对该目标的操作，仅核对并移除锁目录 (unlock-*.lock.d) 与门禁目录 (unlock-*.reclaim-*.gate.d)，切勿删除 unlock-tx-*.json 事务日志及同目录 .old、.bak 恢复材料，随后再执行事务恢复'
        };
      }

      if (wonGate) {
        if (typeof options._onAfterReclaimGateCreated === 'function') {
          await options._onAfterReclaimGateCreated({ gateDir, lockDir, staleOwner, myToken });
        }

        // 分支 B：当前进程获得针对 staleOwner.token 的唯一回收权
        let recheckOwner = null;
        try {
          recheckOwner = JSON.parse(fsImpl.readFileSync(ownerPath, 'utf8'));
        } catch {}
        if (!recheckOwner || recheckOwner.token !== staleOwner.token) {
          cleanupDirSafeSync(prepDir, fsImpl);
          return {
            ok: false,
            code: 'LOCKED_BY_OTHER_PROCESS',
            error: '锁状态已被其他进程更新，请稍后重试'
          };
        }

        const staleDir = path.join(stateDir, `unlock-${targetId}.stale-${staleOwner.token}.d`);
        try {
          fsImpl.renameSync(lockDir, staleDir);
        } catch (moveStaleErr) {
          cleanupDirSafeSync(prepDir, fsImpl);
          try {
            writeJsonAtomicSync(path.join(gateDir, 'reclaimer.json'), {
              ...initialReclaimer,
              status: 'FAILED',
              error: moveStaleErr.message,
              failedAt: Date.now()
            }, fsImpl);
          } catch {}
          return {
            ok: false,
            code: 'RECLAIM_FAILED_MANUAL_INTERVENTION_REQUIRED',
            lockDir,
            gateDir,
            error: `移走陈旧锁目录失败 (${moveStaleErr.message})：请先停止相关操作，仅核对并处理锁目录与门禁目录，保留 unlock-tx-*.json 及 .old、.bak 恢复材料`
          };
        }

        if (typeof options._onAfterStaleLockMoved === 'function') {
          await options._onAfterStaleLockMoved({ staleDir, lockDir, prepDir, gateDir });
        }

        try {
          fsImpl.renameSync(prepDir, lockDir);
        } catch (installNewErr) {
          cleanupDirSafeSync(prepDir, fsImpl);
          cleanupDirSafeSync(staleDir, fsImpl);
          if (fsImpl.existsSync(lockDir)) {
            try {
              writeJsonAtomicSync(path.join(gateDir, 'reclaimer.json'), {
                ...initialReclaimer,
                status: 'OLD_LOCK_RETIRED',
                retiredAt: Date.now()
              }, fsImpl);
            } catch {}
            return {
              ok: false,
              code: 'LOCKED_BY_OTHER_PROCESS',
              error: '陈旧锁已退休，新锁已被其他并发进程取得'
            };
          }
          try {
            writeJsonAtomicSync(path.join(gateDir, 'reclaimer.json'), {
              ...initialReclaimer,
              status: 'FAILED',
              error: installNewErr.message,
              failedAt: Date.now()
            }, fsImpl);
          } catch {}
          return {
            ok: false,
            code: 'RECLAIM_INSTALL_NEW_LOCK_FAILED',
            error: `移入新锁目录失败: ${installNewErr.message}`
          };
        }

        // 复核新锁所有权
        const verifyNew = JSON.parse(fsImpl.readFileSync(ownerPath, 'utf8'));
        if (verifyNew.token !== myToken) {
          cleanupDirSafeSync(staleDir, fsImpl);
          return {
            ok: false,
            code: 'LOCKED_BY_OTHER_PROCESS',
            error: '新锁所有权复核不匹配'
          };
        }
        try {
          writeJsonAtomicSync(path.join(gateDir, 'reclaimer.json'), {
            ...initialReclaimer,
            status: 'COMPLETED',
            completedAt: Date.now()
          }, fsImpl);
        } catch {}
        cleanupDirSafeSync(staleDir, fsImpl);
        acquired = true;
        break;
      }
    }
  }

  if (!acquired) {
    return {
      ok: false,
      code: 'LOCK_ACQUIRE_FAILED',
      error: '无法获取目标文件互斥锁'
    };
  }

  if (typeof options._onAfterLockAcquired === 'function') {
    await options._onAfterLockAcquired({ lockDir, myToken, targetId });
  }

  let fnResult;
  let fnThrown = null;
  try {
    fnResult = await fn({ lockDir, myToken, targetId, stateDir });
  } catch (err) {
    fnThrown = err;
  }

  // 1.4 带短退避重试与结果隔离的释放协议
  let released = false;
  let cleanupWarning = null;
  let lastReleaseErr = null;
  const relDir = path.join(stateDir, `unlock-${targetId}.rel-${myToken}.d`);

  for (let r = 1; r <= 5; r++) {
    try {
      if (!fsImpl.existsSync(lockDir)) {
        released = true;
        break;
      }
      const curRaw = fsImpl.readFileSync(path.join(lockDir, 'owner.json'), 'utf8');
      const curOwner = JSON.parse(curRaw);
      if (curOwner.token !== myToken || curOwner.pid !== process.pid) {
        // 已不属于当前调用，严禁释放
        released = true;
        break;
      }
      fsImpl.renameSync(lockDir, relDir);
      released = true;
      try {
        cleanupDirSafeSync(relDir, fsImpl);
      } catch (cleanErr) {
        cleanupWarning = cleanErr.message;
      }
      break;
    } catch (relErr) {
      lastReleaseErr = relErr;
      if (['EPERM', 'EACCES', 'EBUSY'].includes(relErr.code) && r < 5) {
        await sleepAsync(20);
        continue;
      }
      break;
    }
  }

  if (fnThrown) {
    throw fnThrown;
  }

  if (!released) {
    const lockReleaseError = {
      code: 'LOCK_RELEASE_FAILED',
      lockDir,
      error: lastReleaseErr ? lastReleaseErr.message : '释放锁目录失败'
    };
    if (fnResult && typeof fnResult === 'object') {
      return {
        ...fnResult,
        committed: Boolean(fnResult.committed),
        lockReleaseError
      };
    }
    return {
      ok: false,
      code: 'LOCK_RELEASE_FAILED',
      lockReleaseError
    };
  }

  if (cleanupWarning && fnResult && typeof fnResult === 'object') {
    return { ...fnResult, cleanupWarning };
  }
  return fnResult;
}

// ============================================================================
// 3.1 运行模式强绑定路径解析与 Live 端口反查
// ============================================================================

function resolveBinInDir(binDir, options = {}) {
  const fsImpl = options.fs || fs;
  const allowMissingTarget = Boolean(options.allowMissingTarget);
  const resolvedDir = path.resolve(binDir);
  const candidates = [
    path.join(resolvedDir, 'language_server.exe'),
    path.join(resolvedDir, 'language_server_windows_x64.exe')
  ];

  for (const cand of candidates) {
    if (fsImpl.existsSync(cand)) {
      return { ok: true, binaryPath: cand, binDir: resolvedDir };
    }
  }

  if (allowMissingTarget) {
    // 检查候选路径是否存在未完成事务日志或损坏事务日志
    const activeTxMatches = [];
    for (const cand of candidates) {
      const { txPath } = getTargetArtifactPaths(cand, options);
      const txState = readTxLogStrict(txPath, fsImpl);
      if (
        txState.state === 'CORRUPTED' ||
        (txState.state === 'OK' && txState.tx && !['COMMITTED', 'RECOVERED'].includes(txState.tx.status))
      ) {
        activeTxMatches.push(cand);
      }
    }
    if (activeTxMatches.length > 1) {
      return {
        ok: false,
        code: 'AMBIGUOUS_MISSING_TARGETS',
        candidates: activeTxMatches,
        error: `在 ${resolvedDir} 下发现多个候选文件均存在未完成事务: ${activeTxMatches.join(', ')}`
      };
    }
    if (activeTxMatches.length === 1) {
      return { ok: true, binaryPath: activeTxMatches[0], binDir: resolvedDir, resolvedFromTx: true };
    }

    // 其次检查唯一的 .bak
    const bakMatches = candidates.filter(cand => fsImpl.existsSync(cand + '.bak'));
    if (bakMatches.length === 1) {
      return { ok: true, binaryPath: bakMatches[0], binDir: resolvedDir, resolvedFromBak: true };
    }

    // 检查是否存在已完成但目标被删的事务日志
    const anyTxMatches = candidates.filter(cand => {
      const { txPath } = getTargetArtifactPaths(cand, options);
      return fsImpl.existsSync(txPath);
    });
    if (anyTxMatches.length === 1) {
      return { ok: true, binaryPath: anyTxMatches[0], binDir: resolvedDir, resolvedFromTx: true };
    }

    return { ok: true, binaryPath: candidates[0], binDir: resolvedDir, missing: true };
  }

  return {
    ok: false,
    code: 'BINARY_NOT_FOUND',
    binDir: resolvedDir,
    error: `未在目录 ${resolvedDir} 下找到 language_server.exe 或 language_server_windows_x64.exe`
  };
}

/**
 * 4.3 Live 模式通过端口 -> PID -> ExecutablePath 异步反查运行实例
 */
async function resolveLiveInstanceBinary(origin, options = {}) {
  if (typeof options._resolveLiveInstance === 'function') {
    return await options._resolveLiveInstance(origin, options);
  }
  if ((options.platform || process.platform) !== 'win32') {
    return {
      ok: false,
      code: 'UNSUPPORTED_PLATFORM',
      error: '当前仅支持 Windows x64 桌面端'
    };
  }
  let port = null;
  try {
    const u = new URL(String(origin || ''));
    if (u.hostname !== '127.0.0.1' && u.hostname !== 'localhost') {
      return { ok: false, code: 'LIVE_INSTANCE_UNRESOLVED', error: 'Live origin 不是本机回环地址' };
    }
    const parsedPort = Number(u.port);
    if (Number.isInteger(parsedPort) && parsedPort >= 1 && parsedPort <= 65535) {
      port = parsedPort;
    }
  } catch {}

  if (!port) {
    return { ok: false, code: 'LIVE_INSTANCE_UNRESOLVED', error: '无法从 Live origin 解析合法整数端口' };
  }

  const psScript = [
    `$ErrorActionPreference = 'Stop'`,
    `$conns = @(Get-NetTCPConnection -LocalPort ${port} -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -eq '127.0.0.1' -or $_.LocalAddress -eq '::1' -or $_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::' })`,
    `$pids = @($conns | Select-Object -ExpandProperty OwningProcess -Unique)`,
    `if ($pids.Count -ne 1) { [Console]::Out.Write((@{ ok = $false; reason = 'PID_COUNT_' + $pids.Count } | ConvertTo-Json -Compress)); exit 0 }`,
    `$targetPid = [int]$pids[0]`,
    `$proc = Get-CimInstance Win32_Process -Filter ("ProcessId = " + $targetPid)`,
    `if (-not $proc -or -not $proc.ExecutablePath) { [Console]::Out.Write((@{ ok = $false; reason = 'NO_EXEC_PATH'; pid = $targetPid } | ConvertTo-Json -Compress)); exit 0 }`,
    `$cDate = if ($proc.CreationDate -is [DateTime]) { $proc.CreationDate.ToUniversalTime().ToString('o') } else { [string]$proc.CreationDate }`,
    `[Console]::Out.Write((@{ ok = $true; pid = $targetPid; name = [string]$proc.Name; executablePath = [string]$proc.ExecutablePath; creationDate = $cDate; parentPid = [int]$proc.ParentProcessId } | ConvertTo-Json -Compress))`
  ].join('; ');

  const rawJson = await new Promise(resolve => {
    let stdout = '';
    let done = false;
    const finish = val => {
      if (!done) {
        done = true;
        resolve(val);
      }
    };
    const timer = setTimeout(() => {
      try { child.kill(); } catch {}
      finish(null);
    }, options.timeoutMs || 5000);

    let child;
    try {
      child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-Command', psScript], {
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'ignore']
      });
      child.stdout.on('data', d => { stdout += d.toString('utf8'); });
      child.on('error', () => { clearTimeout(timer); finish(null); });
      child.on('close', () => { clearTimeout(timer); finish(stdout.trim()); });
    } catch {
      clearTimeout(timer);
      finish(null);
    }
  });

  if (!rawJson) {
    return {
      ok: false,
      code: 'LIVE_INSTANCE_UNRESOLVED',
      error: `无法通过端口 ${port} 查询运行中的宿主进程信息`
    };
  }

  let info;
  try {
    info = JSON.parse(rawJson);
  } catch {
    return {
      ok: false,
      code: 'LIVE_INSTANCE_UNRESOLVED',
      error: '解析运行实例进程信息失败'
    };
  }

  if (!info || !info.ok || !info.executablePath) {
    return {
      ok: false,
      code: 'LIVE_INSTANCE_UNRESOLVED',
      error: `无法唯一确认端口 ${port} 所属的进程路径 (${info?.reason || 'UNKNOWN'})`
    };
  }

  const exePath = path.resolve(info.executablePath);
  const exeBase = path.basename(exePath).toLowerCase();
  const canonicalBase = exeBase.replace(/\.old\.\d+$/i, '');
  let binDir = null;

  if (canonicalBase === 'language_server.exe' || canonicalBase === 'language_server_windows_x64.exe') {
    const canonicalExePath = canonicalBase === exeBase
      ? exePath
      : path.join(path.dirname(exePath), path.basename(exePath).replace(/\.old\.\d+$/i, ''));
    return {
      ok: true,
      binaryPath: canonicalExePath,
      binDir: path.dirname(canonicalExePath),
      source: 'live_process',
      instanceIdentity: {
        pid: info.pid,
        creationDate: info.creationDate || '',
        executablePath: exePath,
        port
      }
    };
  }

  // 若监听端口的是 Antigravity.exe (Electron 宿主)，其位于 <InstallDir>/Antigravity.exe，对应 <InstallDir>/resources/bin
  const installDir = path.dirname(exePath);
  const candidateBinDir = path.join(installDir, 'resources', 'bin');
  binDir = candidateBinDir;
  const resolved = resolveBinInDir(binDir, options);
  if (!resolved.ok) {
    return {
      ok: false,
      code: 'LIVE_INSTANCE_UNRESOLVED',
      error: `已定位运行实例 (${exePath})，但未找到对应的语言服务二进制: ${resolved.error}`
    };
  }

  return {
    ok: true,
    ...resolved,
    source: 'live_process',
    instanceIdentity: {
      pid: info.pid,
      creationDate: info.creationDate || '',
      executablePath: exePath,
      port
    }
  };
}

function matchesLiveInstanceIdentity(actual, expected) {
  if (!actual || !expected) return false;
  const aPid = Number(actual.pid);
  const ePid = Number(expected.pid);
  if (!Number.isInteger(aPid) || aPid <= 0 || !Number.isInteger(ePid) || ePid <= 0) return false;
  if (aPid !== ePid) return false;
  if (String(actual.creationDate || '') !== String(expected.creationDate || '')) return false;
  return true;
}

async function verifyLiveInstanceUnchanged(trustedLiveCheck, options = {}) {
  if (!trustedLiveCheck) return { ok: true };
  const targetPath = trustedLiveCheck.binaryPath;
  if (!trustedLiveCheck.origin || !trustedLiveCheck.instanceIdentity) {
    return {
      ok: false,
      code: 'LIVE_INSTANCE_CHANGED_OR_UNRESOLVED',
      targetPath,
      error: 'Live 实例身份上下文缺失，已拒绝写入'
    };
  }
  const recheck = await resolveLiveInstanceBinary(trustedLiveCheck.origin, options);
  if (!recheck || !recheck.ok) {
    return {
      ok: false,
      code: 'LIVE_INSTANCE_CHANGED_OR_UNRESOLVED',
      targetPath,
      error: recheck?.error || '写入前复核运行实例失败：端口归属不可解析或进程已退出'
    };
  }
  if (
    !matchesLiveInstanceIdentity(recheck.instanceIdentity, trustedLiveCheck.instanceIdentity) ||
    normalizeTargetPathKey(recheck.binaryPath) !== normalizeTargetPathKey(targetPath)
  ) {
    return {
      ok: false,
      code: 'LIVE_INSTANCE_CHANGED_OR_UNRESOLVED',
      targetPath,
      expectedInstanceIdentity: trustedLiveCheck.instanceIdentity,
      actualInstanceIdentity: recheck.instanceIdentity || null,
      error: '检测到运行中的语言服务实例已重启或端口归属发生变化，已中止操作'
    };
  }
  return { ok: true, instanceIdentity: recheck.instanceIdentity };
}

async function resolveTargetBinary(options = {}, resolveOpts = {}) {
  const fsImpl = options.fs || fs;
  const allowMissingTarget = Boolean(resolveOpts.allowMissingTarget || options.allowMissingTarget);
  const platform = options.platform || process.platform;
  if (platform !== 'win32') {
    return {
      ok: false,
      unsupportedPlatform: true,
      code: 'UNSUPPORTED_PLATFORM',
      error: '当前仅支持 Windows x64 桌面端后端 (language_server.exe)'
    };
  }

  const runtimeMode = options.runtimeMode || (process.versions?.electron ? 'electron' : 'cli');

  // 1. Electron 主进程模式：忽略外部传入的 binaryPath，强制绑定当前宿主 process.resourcesPath
  if (runtimeMode === 'electron') {
    const resPath = options._testResourcesPath || process.resourcesPath;
    if (!resPath) {
      return {
        ok: false,
        code: 'ELECTRON_RESOURCES_PATH_MISSING',
        error: 'Electron 主进程缺少 process.resourcesPath，无法定位当前宿主目录'
      };
    }
    const binDir = path.join(resPath, 'bin');
    const res = resolveBinInDir(binDir, { ...options, allowMissingTarget, fs: fsImpl });
    return { ...res, runtimeMode: 'electron', source: 'electron_host' };
  }

  // 2. Live 模式：忽略外部传入的 binaryPath，强制从当前连接的运行实例反查
  if (runtimeMode === 'live') {
    const liveRes = await resolveLiveInstanceBinary(options.origin, { ...options, allowMissingTarget, fs: fsImpl });
    return { ...liveRes, runtimeMode: 'live' };
  }

  // 3. CLI 模式：允许显式 --binary 路径
  if (options.binaryPath && typeof options.binaryPath === 'string' && options.binaryPath.trim()) {
    const explicitPath = path.resolve(options.binaryPath.trim());
    const parentDir = path.dirname(explicitPath);
    if (!fsImpl.existsSync(parentDir)) {
      return {
        ok: false,
        code: 'BINARY_DIR_NOT_FOUND',
        binaryPath: explicitPath,
        error: `指定路径的父目录不存在: ${parentDir}`
      };
    }
    if (!allowMissingTarget && !fsImpl.existsSync(explicitPath)) {
      return {
        ok: false,
        code: 'BINARY_NOT_FOUND',
        binaryPath: explicitPath,
        error: `指定的目标文件不存在: ${explicitPath}`
      };
    }
    return {
      ok: true,
      binaryPath: explicitPath,
      binDir: parentDir,
      runtimeMode: 'cli',
      source: 'explicit_binary'
    };
  }

  // CLI 回退 1：检查状态目录中的 installation.json
  const stateDir = resolveUnlockStateDir(options);
  const installManifestPath = path.join(stateDir, 'installation.json');
  if (fsImpl.existsSync(installManifestPath)) {
    try {
      const inst = JSON.parse(fsImpl.readFileSync(installManifestPath, 'utf8'));
      if (inst && typeof inst.installed === 'string') {
        const resourcesDir = path.dirname(path.resolve(inst.installed));
        const binDir = path.join(resourcesDir, 'bin');
        if (fsImpl.existsSync(binDir)) {
          const res = resolveBinInDir(binDir, { ...options, allowMissingTarget, fs: fsImpl });
          if (res.ok) {
            return { ...res, runtimeMode: 'cli', source: 'installation_manifest' };
          }
        }
      }
    } catch {}
  }

  // CLI 回退 2：标准安装目录候选
  const home = os.homedir();
  const localAppData = process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local');
  const programFiles = process.env.ProgramFiles || 'C:\\Program Files';
  const candidateBinDirs = [
    path.join(localAppData, 'Programs', 'antigravity', 'resources', 'bin'),
    path.join(programFiles, 'antigravity', 'resources', 'bin'),
    path.join(programFiles, 'Google Antigravity', 'resources', 'bin'),
    path.join(home, 'AppData', 'Roaming', 'antigravity', 'resources', 'bin')
  ];

  for (const binDir of candidateBinDirs) {
    if (fsImpl.existsSync(binDir)) {
      const res = resolveBinInDir(binDir, { ...options, allowMissingTarget, fs: fsImpl });
      if (res.ok) {
        return { ...res, runtimeMode: 'cli', source: 'default_candidates' };
      }
    }
  }

  return {
    ok: false,
    code: 'BINARY_NOT_FOUND',
    error: '未能自动探测到 Antigravity 后端 language_server.exe，请使用 --binary 指定路径'
  };
}

// ============================================================================
// 4.1 & 4.2 运行状态、有据清理与核心业务操作 (status / dryRun / apply / restore / recover)
// ============================================================================

// 记录当前宿主进程首次观测到的各 targetId 磁盘 SHA256 及本会话写入标记
const initialObservedDiskSha = new Map();
const modifiedInCurrentProcess = new Set();

function mergeRetiredOldFiles(...lists) {
  const byPath = new Map();
  for (const list of lists) {
    if (!Array.isArray(list)) continue;
    for (const item of list) {
      if (!item || typeof item.oldPath !== 'string' || typeof item.sha256 !== 'string') continue;
      const key = normalizeTargetPathKey(item.oldPath);
      if (!byPath.has(key)) {
        byPath.set(key, item);
      }
    }
  }
  return Array.from(byPath.values());
}

function hasMissingRetiredOldFiles(currentList, requiredList) {
  if (!Array.isArray(requiredList) || requiredList.length === 0) return false;
  const known = new Set(
    (Array.isArray(currentList) ? currentList : [])
      .filter(item => item && typeof item.oldPath === 'string')
      .map(item => normalizeTargetPathKey(item.oldPath))
  );
  for (const req of requiredList) {
    if (req && typeof req.oldPath === 'string' && !known.has(normalizeTargetPathKey(req.oldPath))) {
      return true;
    }
  }
  return false;
}

function countRemainingRetiredOldFiles(manifest, fsImpl = fs) {
  if (!manifest || !Array.isArray(manifest.retiredOldFiles)) return 0;
  let count = 0;
  for (const item of manifest.retiredOldFiles) {
    if (item && typeof item.oldPath === 'string' && fsImpl.existsSync(item.oldPath)) {
      count++;
    }
  }
  return count;
}

/**
 * 4.2 持锁清理 manifest.retiredOldFiles 中有来源记录且哈希匹配的旧文件
 */
function cleanupRetiredOldFilesInLock(manifest, fsImpl = fs) {
  if (!manifest || !Array.isArray(manifest.retiredOldFiles) || manifest.retiredOldFiles.length === 0) {
    return { cleanedCount: 0, remaining: [] };
  }
  const remaining = [];
  let cleanedCount = 0;
  for (const entry of manifest.retiredOldFiles) {
    if (!entry || typeof entry.oldPath !== 'string' || typeof entry.sha256 !== 'string') {
      continue;
    }
    try {
      if (!fsImpl.existsSync(entry.oldPath)) {
        cleanedCount++;
        continue;
      }
      const actualSha = sha256FileSync(entry.oldPath, fsImpl);
      if (actualSha !== entry.sha256) {
        // 哈希不匹配：来源存疑，不自动删除，但保留记录以供诊断
        remaining.push(entry);
        continue;
      }
      fsImpl.unlinkSync(entry.oldPath);
      cleanedCount++;
    } catch {
      // 仍被进程占用锁定，保留记录等下次清理
      remaining.push(entry);
    }
  }
  return { cleanedCount, remaining };
}

/**
 * 只读状态查询 (getUnlockStatusInternal) — 绝不创建目录、绝不删除或修改任何文件
 */
async function getUnlockStatusInternal(options = {}) {
  const fsImpl = options.fs || fs;
  const resolved = await resolveTargetBinary(options, { allowMissingTarget: true });
  if (!resolved.ok) {
    return resolved;
  }

  const targetPath = resolved.binaryPath;
  const bakPath = `${targetPath}.bak`;
  const { targetId, lockDir, txPath, manifestPath } = getTargetArtifactPaths(targetPath, options);

  const txCheck = readTxLogStrict(txPath, fsImpl);
  let manifest = null;
  if (fsImpl.existsSync(manifestPath)) {
    try {
      manifest = JSON.parse(fsImpl.readFileSync(manifestPath, 'utf8'));
    } catch {}
  }

  const targetExists = fsImpl.existsSync(targetPath);
  const bakExists = fsImpl.existsSync(bakPath);
  const lockExists = fsImpl.existsSync(lockDir);

  if (txCheck.state === 'CORRUPTED') {
    return {
      ok: true,
      status: 'corrupted_transaction_log',
      code: 'CORRUPTED_TRANSACTION_LOG',
      targetPath,
      bakPath,
      targetId,
      runtimeMode: resolved.runtimeMode,
      source: resolved.source,
      targetExists,
      bakExists,
      lockExists,
      canWrite: false,
      canRestore: false,
      needsRecovery: true,
      error: txCheck.error
    };
  }

  const activeTx = txCheck.state === 'OK' && txCheck.tx && !['COMMITTED', 'RECOVERED'].includes(txCheck.tx.status)
    ? txCheck.tx
    : null;

  if (!targetExists) {
    return {
      ok: true,
      status: activeTx ? 'interrupted_transaction' : 'target_missing',
      code: activeTx ? 'UNFINISHED_TRANSACTION' : 'TARGET_MISSING_NO_ACTIVE_TX',
      targetPath,
      bakPath,
      targetId,
      runtimeMode: resolved.runtimeMode,
      source: resolved.source,
      targetExists: false,
      bakExists,
      lockExists,
      activeTransaction: activeTx,
      recoverySourcePath: activeTx?.oldPath || null,
      canWrite: false,
      canRestore: false,
      needsRecovery: Boolean(activeTx),
      error: activeTx
        ? `检测到未完成的替换事务 (${activeTx.status})，原文件位于 ${activeTx.oldPath || '未知'}，请点击恢复`
        : `未找到目标二进制文件: ${targetPath}`
    };
  }

  const currentBuf = fsImpl.readFileSync(targetPath);
  const currentSha256 = sha256Buffer(currentBuf);
  if (!initialObservedDiskSha.has(targetId)) {
    initialObservedDiskSha.set(targetId, currentSha256);
  }

  let backupVerify = { valid: false, reason: '未找到同目录 .bak 备份文件' };
  let bakSha256 = null;
  if (bakExists) {
    try {
      const bakBuf = fsImpl.readFileSync(bakPath);
      bakSha256 = sha256Buffer(bakBuf);
      backupVerify = verifySameBuildBackup(currentBuf, bakBuf);
    } catch (e) {
      backupVerify = { valid: false, reason: `读取备份失败: ${e.message}` };
    }
  }

  const inspectRes = backupVerify.valid && backupVerify.currentInspect
    ? backupVerify.currentInspect
    : inspectBinaryBuffer(currentBuf);

  if (!inspectRes.ok) {
    return {
      ok: false,
      code: inspectRes.code || 'INSPECT_FAILED',
      targetPath,
      bakPath,
      targetId,
      runtimeMode: resolved.runtimeMode,
      source: resolved.source,
      sha256: currentSha256,
      bakExists,
      backupValid: false,
      error: inspectRes.error
    };
  }

  const canUseCurrentAsBase = inspectRes.isUnpatchedOriginal;
  const hasVerifiedBase = canUseCurrentAsBase || backupVerify.valid;
  const canWrite = !activeTx && hasVerifiedBase && !inspectRes.isUnverifiedExternal;
  const canRestore = !activeTx && backupVerify.valid && (!inspectRes.isUnpatchedOriginal || currentSha256 !== bakSha256);

  const runtimeState =
    modifiedInCurrentProcess.has(targetId) || initialObservedDiskSha.get(targetId) !== currentSha256
      ? 'pending_restart'
      : 'unknown';

  const terminalTx = txCheck.state === 'OK' && txCheck.tx && ['COMMITTED', 'RECOVERED'].includes(txCheck.tx.status)
    ? txCheck.tx
    : null;
  const mergedRetiredOldFiles = mergeRetiredOldFiles(
    manifest?.retiredOldFiles,
    terminalTx?.pendingManifest?.retiredOldFiles
  );
  const committedOldFiles = countRemainingRetiredOldFiles({ retiredOldFiles: mergedRetiredOldFiles }, fsImpl);
  const manifestSyncPending = Boolean(
    terminalTx &&
    terminalTx.status === 'COMMITTED' &&
    terminalTx.pendingManifest &&
    currentSha256 === terminalTx.afterSha256 &&
    (
      !manifest ||
      manifest.patchedSha256 !== terminalTx.afterSha256 ||
      hasMissingRetiredOldFiles(manifest.retiredOldFiles, terminalTx.pendingManifest.retiredOldFiles)
    )
  );

  return {
    ok: true,
    status: activeTx
      ? 'interrupted_transaction'
      : inspectRes.isUnverifiedExternal
        ? 'unverified_external_patch'
        : inspectRes.isMixedState
          ? 'mixed_patched'
          : inspectRes.isUnpatchedOriginal
            ? 'original_256k'
            : 'patched',
    targetPath,
    bakPath,
    targetId,
    runtimeMode: resolved.runtimeMode,
    source: resolved.source,
    instanceIdentity: resolved.instanceIdentity || null,
    diskState: {
      overallState: inspectRes.overallState,
      mode: inspectRes.gate3a.mode,
      capTokens: inspectRes.gate3a.capTokens,
      label: inspectRes.gate3a.label,
      gate3a: inspectRes.gate3a,
      gate3b: inspectRes.gate3b,
      sha256: currentSha256
    },
    backupState: {
      exists: bakExists,
      validSameBuild: backupVerify.valid,
      sha256: bakSha256,
      reason: backupVerify.valid ? '同构建原版备份已就绪 (.bak)' : backupVerify.reason
    },
    runtimeState,
    cleanupState: {
      committedOldFiles
    },
    manifestSyncPending,
    activeTransaction: activeTx,
    needsRecovery: Boolean(activeTx),
    canWrite,
    canRestore
  };
}

/**
 * 2.4 纯只读预检 (dryRunUnlock) — 不获取锁、不写 .bak、不写任何日志
 */
async function dryRunUnlockInternal(options = {}) {
  const fsImpl = options.fs || fs;
  const resolved = await resolveTargetBinary(options, { allowMissingTarget: true });
  if (!resolved.ok) return resolved;

  const targetPath = resolved.binaryPath;
  const bakPath = `${targetPath}.bak`;
  const { targetId, txPath } = getTargetArtifactPaths(targetPath, options);

  const txCheck = readTxLogStrict(txPath, fsImpl);
  if (txCheck.state === 'CORRUPTED') {
    return {
      ok: false,
      code: 'CORRUPTED_TRANSACTION_LOG',
      targetPath,
      error: txCheck.error
    };
  }
  if (txCheck.state === 'OK' && txCheck.tx && !['COMMITTED', 'RECOVERED'].includes(txCheck.tx.status)) {
    return {
      ok: false,
      code: 'UNFINISHED_TRANSACTION',
      targetPath,
      tx: txCheck.tx,
      error: '该目标存在未完成的替换事务，请先执行恢复操作'
    };
  }
  if (!fsImpl.existsSync(targetPath)) {
    return {
      ok: false,
      code: 'BINARY_NOT_FOUND',
      targetPath,
      error: `未找到目标二进制文件: ${targetPath}`
    };
  }

  let spec;
  try {
    spec = normalizeTargetSpec(options);
  } catch (err) {
    return { ok: false, code: err.code || 'INVALID_TIER_SPEC', error: err.message };
  }

  const currentBuf = fsImpl.readFileSync(targetPath);
  const currentInspect = inspectBinaryBuffer(currentBuf);
  if (!currentInspect.ok) {
    return {
      ok: false,
      code: currentInspect.code || 'INSPECT_FAILED',
      targetPath,
      error: currentInspect.error
    };
  }

  let baseOriginalBuf = null;
  if (currentInspect.isUnpatchedOriginal) {
    baseOriginalBuf = currentBuf;
  } else {
    if (!fsImpl.existsSync(bakPath)) {
      return {
        ok: false,
        code: 'REFUSED_NO_VERIFIED_BACKUP',
        targetPath,
        error: '当前二进制处于已修改状态且缺少同目录 .bak 原版备份，拒绝预检或继续写入'
      };
    }
    const bakBuf = fsImpl.readFileSync(bakPath);
    const verify = verifySameBuildBackup(currentBuf, bakBuf);
    if (!verify.valid) {
      return {
        ok: false,
        code: verify.code === 'CORRUPTED_GATE3B' ? 'CORRUPTED_GATE3B' : 'REFUSED_NO_VERIFIED_BACKUP',
        targetPath,
        error: `拒绝操作：${verify.reason}`
      };
    }
    baseOriginalBuf = bakBuf;
  }

  try {
    const built = buildTargetImageFromOriginalBase(baseOriginalBuf, spec, currentBuf);
    return {
      ok: true,
      dryRun: true,
      targetPath,
      bakPath,
      targetId,
      runtimeMode: resolved.runtimeMode,
      source: resolved.source,
      instanceIdentity: resolved.instanceIdentity || null,
      changed: built.changed,
      beforeSha256: built.beforeSha256,
      afterSha256: built.afterSha256,
      baseOriginalSha256: built.baseOriginalSha256,
      targetSpec: built.spec,
      gate3a: built.gate3a,
      gate3b: built.gate3b
    };
  } catch (err) {
    return {
      ok: false,
      code: err.code || 'DRY_RUN_FAILED',
      targetPath,
      error: err.message
    };
  }
}

/**
 * 3.3.3 锁内原子建立备份与三阶段事务写入 (applyUnlockInternal)
 */
async function applyUnlockInternal(options = {}) {
  const fsImpl = options.fs || fs;
  const resolved = options._preResolvedTarget || await resolveTargetBinary(options, { allowMissingTarget: true });
  if (!resolved.ok) return resolved;

  const targetPath = resolved.binaryPath;
  const bakPath = `${targetPath}.bak`;
  const { targetId, txPath, manifestPath, backupsDir } = getTargetArtifactPaths(targetPath, options);

  // Live 模式：建立可信实例身份上下文（启动前首轮校验 + 锁内替换前二次复核）
  let trustedLiveCheck = options._trustedLiveCheck || null;
  if (resolved.runtimeMode === 'live') {
    if (!resolved.instanceIdentity) {
      return {
        ok: false,
        code: 'LIVE_INSTANCE_CHANGED_OR_UNRESOLVED',
        targetPath,
        error: '未能获取可信的运行实例身份，已拒绝写入'
      };
    }
    if (options.expectedInstanceIdentity && !matchesLiveInstanceIdentity(resolved.instanceIdentity, options.expectedInstanceIdentity)) {
      return {
        ok: false,
        code: 'LIVE_INSTANCE_CHANGED_OR_UNRESOLVED',
        targetPath,
        error: '检测到运行中的语言服务实例已重启或发生变化，请重新预检后再应用'
      };
    }
    if (!trustedLiveCheck) {
      trustedLiveCheck = {
        origin: options.origin,
        binaryPath: targetPath,
        instanceIdentity: resolved.instanceIdentity
      };
    }
  }

  let spec;
  try {
    spec = normalizeTargetSpec(options);
  } catch (err) {
    return { ok: false, code: err.code || 'INVALID_TIER_SPEC', error: err.message };
  }

  return await withUnlockLock(targetPath, async () => {
    // 1. 写前事务门禁
    const txCheck = readTxLogStrict(txPath, fsImpl);
    if (txCheck.state === 'CORRUPTED') {
      return {
        ok: false,
        code: 'CORRUPTED_TRANSACTION_LOG',
        targetPath,
        txPath,
        error: txCheck.error
      };
    }
    if (txCheck.state === 'OK' && txCheck.tx && !['COMMITTED', 'RECOVERED'].includes(txCheck.tx.status)) {
      return {
        ok: false,
        code: 'UNFINISHED_TRANSACTION',
        targetPath,
        tx: txCheck.tx,
        error: '该目标存在未完成的替换事务，请先执行恢复操作'
      };
    }

    // 2. 重读并校验当前文件（绕过一切缓存）
    if (!fsImpl.existsSync(targetPath)) {
      return {
        ok: false,
        code: 'BINARY_NOT_FOUND',
        targetPath,
        error: `目标二进制文件不存在: ${targetPath}`
      };
    }
    const currentBuf = fsImpl.readFileSync(targetPath);
    const beforeSha256 = sha256Buffer(currentBuf);

    if (options.expectedBeforeSha256 && options.expectedBeforeSha256.toLowerCase() !== beforeSha256) {
      return {
        ok: false,
        code: 'EXPECTED_HASH_MISMATCH',
        targetPath,
        expectedBeforeSha256: options.expectedBeforeSha256,
        actualBeforeSha256: beforeSha256,
        error: '目标文件自上次预检后已发生改变，请重新检测状态'
      };
    }

    const staticInspect = inspectBinaryBuffer(currentBuf);
    if (!staticInspect.ok) {
      return {
        ok: false,
        code: staticInspect.code || 'INSPECT_FAILED',
        targetPath,
        error: staticInspect.error
      };
    }

    // 2.5 Live 模式在 Worker 持锁且发生任何磁盘改动前，再次复核端口归属与 (pid, creationDate)
    if (trustedLiveCheck) {
      const liveRecheck = await verifyLiveInstanceUnchanged(trustedLiveCheck, {
        ...options,
        allowMissingTarget: false,
        fs: fsImpl
      });
      if (!liveRecheck.ok) {
        return liveRecheck;
      }
    }

    // 3. 锁内原子建立或验证同构建 .bak
    let bakBuf = null;
    if (staticInspect.isUnpatchedOriginal && !options._requireExistingBackup) {
      let needWriteBak = !fsImpl.existsSync(bakPath);
      if (!needWriteBak) {
        const existingBakBuf = fsImpl.readFileSync(bakPath);
        if (sha256Buffer(existingBakBuf) !== beforeSha256) {
          // 归档旧版本 .bak
          try {
            fsImpl.mkdirSync(backupsDir, { recursive: true });
            const oldSha8 = sha256Buffer(existingBakBuf).slice(0, 8);
            const archivePath = path.join(backupsDir, `${path.basename(targetPath)}-${oldSha8}.bak`);
            if (!fsImpl.existsSync(archivePath)) {
              fsImpl.copyFileSync(bakPath, archivePath);
            }
          } catch {}
          needWriteBak = true;
        } else {
          bakBuf = existingBakBuf;
        }
      }

      if (needWriteBak) {
        const bakTmp = `${bakPath}.tmp.${process.pid}.${Date.now()}`;
        let bfd = null;
        try {
          bfd = fsImpl.openSync(bakTmp, 'w');
          fsImpl.writeSync(bfd, currentBuf, 0, currentBuf.length, 0);
          fsImpl.fsyncSync(bfd);
          fsImpl.closeSync(bfd);
          bfd = null;
          if (sha256FileSync(bakTmp, fsImpl) !== beforeSha256) {
            throw new Error('备份临时文件读回哈希不匹配');
          }
          fsImpl.renameSync(bakTmp, bakPath);
          bakBuf = fsImpl.readFileSync(bakPath);
          if (sha256Buffer(bakBuf) !== beforeSha256) {
            throw new Error('备份文件最终校验哈希不匹配');
          }
        } catch (bakErr) {
          if (bfd !== null) {
            try { fsImpl.closeSync(bfd); } catch {}
          }
          try {
            if (fsImpl.existsSync(bakTmp)) fsImpl.unlinkSync(bakTmp);
          } catch {}
          return {
            ok: false,
            code: 'BACKUP_WRITE_FAILED',
            targetPath,
            bakPath,
            error: `创建原版备份 (.bak) 失败，已中止修改: ${bakErr.message}`
          };
        }
      }
    } else {
      if (!fsImpl.existsSync(bakPath)) {
        return {
          ok: false,
          code: 'REFUSED_NO_VERIFIED_BACKUP',
          targetPath,
          bakPath,
          error: '当前二进制已被修改且缺少匹配的同版本原版备份 (.bak)，已禁止继续写入'
        };
      }
      bakBuf = fsImpl.readFileSync(bakPath);
    }

    const verifyBak = verifySameBuildBackup(currentBuf, bakBuf);
    if (!verifyBak.valid) {
      return {
        ok: false,
        code: verifyBak.code === 'CORRUPTED_GATE3B' ? 'CORRUPTED_GATE3B' : 'REFUSED_NO_VERIFIED_BACKUP',
        targetPath,
        bakPath,
        error: `备份等价校验未通过：${verifyBak.reason}`
      };
    }

    const verifiedBakSha256 = sha256Buffer(bakBuf);

    // 3.5 在覆盖终态事务日志或提前返回前，可靠合并现有 manifest 与历史终态事务中的 retiredOldFiles，并尽力补齐未同步的 manifest
    let existingManifest = null;
    let manifestRetiredOldFiles = [];
    if (fsImpl.existsSync(manifestPath)) {
      try {
        existingManifest = JSON.parse(fsImpl.readFileSync(manifestPath, 'utf8'));
        if (Array.isArray(existingManifest?.retiredOldFiles)) {
          manifestRetiredOldFiles = existingManifest.retiredOldFiles;
        }
      } catch {}
    }
    const prevTx = (txCheck.state === 'OK' && txCheck.tx) ? txCheck.tx : null;
    const txRetiredOldFiles = Array.isArray(prevTx?.pendingManifest?.retiredOldFiles)
      ? prevTx.pendingManifest.retiredOldFiles
      : [];
    const prevRetiredOldFiles = mergeRetiredOldFiles(manifestRetiredOldFiles, txRetiredOldFiles);

    if (prevTx && prevTx.status === 'COMMITTED' && prevTx.pendingManifest) {
      const needPreSyncManifest =
        !existingManifest ||
        (beforeSha256 === prevTx.afterSha256 && existingManifest.patchedSha256 !== prevTx.afterSha256) ||
        hasMissingRetiredOldFiles(existingManifest.retiredOldFiles, prevRetiredOldFiles);
      if (needPreSyncManifest) {
        const preSyncBase = beforeSha256 === prevTx.afterSha256
          ? prevTx.pendingManifest
          : (existingManifest || prevTx.pendingManifest);
        try {
          writeJsonAtomicSync(manifestPath, {
            ...preSyncBase,
            retiredOldFiles: prevRetiredOldFiles
          }, fsImpl);
        } catch {
          // 若此刻 manifest 仍暂时不可写，prevRetiredOldFiles 已合并进入内存，将继续写入新事务 pendingManifest
        }
      }
    }

    // 4. 基于已验证的 bakBuf 生成目标完整镜像
    const built = buildTargetImageFromOriginalBase(bakBuf, spec, currentBuf);
    if (!built.changed) {
      return {
        ok: true,
        changed: false,
        committed: false,
        targetPath,
        bakPath,
        targetId,
        beforeSha256,
        afterSha256: built.afterSha256,
        appliedSpec: built.spec,
        runtimeState: modifiedInCurrentProcess.has(targetId) ? 'pending_restart' : 'unknown'
      };
    }

    const afterSha256 = built.afterSha256;
    const now = Date.now();
    const txId = `tx-${now}-${crypto.randomBytes(4).toString('hex')}`;
    const stagedPath = `${targetPath}.staged.${process.pid}.${now}.exe`;
    const oldPath = `${targetPath}.old.${now}`;

    // 阶段 0：写出 stagedPath 并 fsync + 读回校验
    let sfd = null;
    try {
      sfd = fsImpl.openSync(stagedPath, 'w');
      fsImpl.writeSync(sfd, built.buffer, 0, built.buffer.length, 0);
      fsImpl.fsyncSync(sfd);
      fsImpl.closeSync(sfd);
      sfd = null;
      if (sha256FileSync(stagedPath, fsImpl) !== afterSha256) {
        throw new Error('Staged 临时二进制文件读回哈希不匹配');
      }
    } catch (stageErr) {
      if (sfd !== null) {
        try { fsImpl.closeSync(sfd); } catch {}
      }
      try {
        if (fsImpl.existsSync(stagedPath)) fsImpl.unlinkSync(stagedPath);
      } catch {}
      return {
        ok: false,
        code: 'STAGE_WRITE_FAILED',
        targetPath,
        error: `写出临时补丁文件失败: ${stageErr.message}`
      };
    }

    const baseManifest = {
      targetId,
      binaryPath: targetPath,
      backupPath: bakPath,
      originalSha256: verifiedBakSha256,
      patchedSha256: afterSha256,
      appliedMode: built.spec.mode,
      appliedCapTokens: built.spec.capTokens,
      appliedLabel: built.spec.label,
      updatedAt: new Date(now).toISOString(),
      retiredOldFiles: prevRetiredOldFiles
    };

    const txRecord = {
      txId,
      targetId,
      targetPath,
      bakPath,
      stagedPath,
      oldPath,
      beforeSha256,
      afterSha256,
      verifiedBakSha256,
      targetSpec: built.spec,
      status: 'PREPARED',
      startedAt: now,
      pendingManifest: baseManifest
    };

    writeJsonAtomicSync(txPath, txRecord, fsImpl);

    if (typeof options._onAfterTxPrepared === 'function') {
      await options._onAfterTxPrepared({ txRecord, txPath });
    }

    const finalizePostCommit = async (method, manifestBeforeClean) => {
      modifiedInCurrentProcess.add(targetId);
      const cleanRes = cleanupRetiredOldFilesInLock(manifestBeforeClean, fsImpl);
      const finalManifest = { ...manifestBeforeClean, retiredOldFiles: cleanRes.remaining };
      const extraFields = method === 'hot_rename' ? { oldPath } : {};

      try {
        writeJsonAtomicSync(txPath, {
          ...txRecord,
          status: 'COMMITTED',
          method,
          oldPath: method === 'hot_rename' ? oldPath : null,
          committedAt: Date.now(),
          pendingManifest: finalManifest
        }, fsImpl);
      } catch (txCommitErr) {
        return {
          ok: false,
          partialSuccess: true,
          changed: true,
          committed: true,
          manifestSynced: false,
          code: 'POST_COMMIT_TX_LOG_SYNC_FAILED',
          error: `二进制补丁已落盘替换，但写入已提交事务记录失败 (${txCommitErr.code || txCommitErr.message})`,
          txSyncError: {
            code: txCommitErr.code || 'TX_LOG_WRITE_FAILED',
            txPath,
            error: txCommitErr.message
          },
          method,
          ...extraFields,
          targetPath,
          bakPath,
          targetId,
          beforeSha256,
          afterSha256,
          appliedSpec: built.spec,
          runtimeState: 'pending_restart',
          cleanupState: { committedOldFiles: cleanRes.remaining.length }
        };
      }

      if (typeof options._onBeforeManifestWriteAfterCommit === 'function') {
        await options._onBeforeManifestWriteAfterCommit({ txPath, manifestPath });
      }

      try {
        writeJsonAtomicSync(manifestPath, finalManifest, fsImpl);
      } catch (manifestErr) {
        return {
          ok: false,
          partialSuccess: true,
          changed: true,
          committed: true,
          manifestSynced: false,
          code: 'POST_COMMIT_MANIFEST_SYNC_FAILED',
          error: `二进制补丁已提交落盘，但同步状态清单失败 (${manifestErr.code || manifestErr.message})；下次写入或执行恢复时将自动补齐`,
          manifestSyncError: {
            code: manifestErr.code || 'MANIFEST_WRITE_FAILED',
            manifestPath,
            error: manifestErr.message
          },
          method,
          ...extraFields,
          targetPath,
          bakPath,
          targetId,
          beforeSha256,
          afterSha256,
          appliedSpec: built.spec,
          runtimeState: 'pending_restart',
          cleanupState: { committedOldFiles: cleanRes.remaining.length }
        };
      }

      return {
        ok: true,
        changed: true,
        committed: true,
        manifestSynced: true,
        method,
        ...extraFields,
        targetPath,
        bakPath,
        targetId,
        beforeSha256,
        afterSha256,
        appliedSpec: built.spec,
        runtimeState: 'pending_restart',
        cleanupState: { committedOldFiles: cleanRes.remaining.length }
      };
    };

    // 阶段 1：尝试直接替换 (direct_replace)
    if (!options._forceHotRename) {
      let directReplaced = false;
      try {
        fsImpl.renameSync(stagedPath, targetPath);
        directReplaced = true;
      } catch (err) {
        if (!['EPERM', 'EACCES', 'EBUSY'].includes(err.code)) {
          try { if (fsImpl.existsSync(stagedPath)) fsImpl.unlinkSync(stagedPath); } catch {}
          writeJsonAtomicSync(txPath, { ...txRecord, status: 'RECOVERED', abortedError: err.message }, fsImpl);
          return {
            ok: false,
            code: 'DIRECT_REPLACE_FAILED',
            targetPath,
            error: `替换目标文件失败: ${err.message}`
          };
        }
      }

      if (directReplaced) {
        if (sha256FileSync(targetPath, fsImpl) !== afterSha256) {
          return {
            ok: false,
            code: 'POST_VERIFY_MISMATCH',
            targetPath,
            error: '直接替换后目标文件哈希复核不匹配'
          };
        }
        return await finalizePostCommit('direct_replace', baseManifest);
      }
    }

    // 阶段 2：尽力而为热重命名 (hot_rename)
    writeJsonAtomicSync(txPath, { ...txRecord, status: 'MOVING_OLD' }, fsImpl);

    try {
      fsImpl.renameSync(targetPath, oldPath);
    } catch (moveOldErr) {
      try { if (fsImpl.existsSync(stagedPath)) fsImpl.unlinkSync(stagedPath); } catch {}
      writeJsonAtomicSync(txPath, { ...txRecord, status: 'RECOVERED', hotRenameBlocked: moveOldErr.message }, fsImpl);
      return {
        ok: false,
        code: 'HOT_RENAME_BLOCKED',
        targetPath,
        error: `当前运行中的进程句柄或目录权限阻止了热重命名 (${moveOldErr.code || moveOldErr.message})，请先关闭 Antigravity 客户端后再试`
      };
    }

    const manifestWithOld = {
      ...baseManifest,
      retiredOldFiles: mergeRetiredOldFiles(prevRetiredOldFiles, [
        { oldPath, sha256: beforeSha256, txId, committedAt: Date.now() }
      ])
    };

    writeJsonAtomicSync(txPath, {
      ...txRecord,
      status: 'OLD_MOVED',
      pendingManifest: manifestWithOld
    }, fsImpl);

    if (typeof options._onAfterOldMoved === 'function') {
      await options._onAfterOldMoved({ txPath, targetPath, oldPath, stagedPath });
    }

    try {
      fsImpl.renameSync(stagedPath, targetPath);
    } catch (moveStageErr) {
      // 立即尝试回滚 oldPath -> targetPath
      try {
        fsImpl.renameSync(oldPath, targetPath);
        if (sha256FileSync(targetPath, fsImpl) !== beforeSha256) {
          throw new Error('回滚后哈希不匹配');
        }
        try { if (fsImpl.existsSync(stagedPath)) fsImpl.unlinkSync(stagedPath); } catch {}
        writeJsonAtomicSync(txPath, {
          ...txRecord,
          status: 'RECOVERED',
          rolledBackAt: Date.now(),
          stageMoveError: moveStageErr.message
        }, fsImpl);
        return {
          ok: false,
          code: 'STAGE_MOVE_FAILED_ROLLED_BACK',
          targetPath,
          error: `新文件移入失败 (${moveStageErr.message})，已自动将原文件回滚恢复`
        };
      } catch (rollbackErr) {
        writeJsonAtomicSync(txPath, {
          ...txRecord,
          status: 'ROLLBACK_FAILED',
          stageMoveError: moveStageErr.message,
          rollbackError: rollbackErr.message,
          failedAt: Date.now()
        }, fsImpl);
        return {
          ok: false,
          code: 'ROLLBACK_FAILED',
          targetPath,
          recoverySourcePath: oldPath,
          stagedPath,
          error: `新文件移入失败且自动回滚受阻！原文件保存在 ${oldPath}，请点击「恢复中断事务」或手动将其重命名回 ${path.basename(targetPath)}`
        };
      }
    }

    if (sha256FileSync(targetPath, fsImpl) !== afterSha256) {
      return {
        ok: false,
        code: 'POST_VERIFY_MISMATCH',
        targetPath,
        recoverySourcePath: oldPath,
        error: '热重命名后目标文件哈希复核不匹配'
      };
    }

    return await finalizePostCommit('hot_rename', manifestWithOld);
  }, options);
}

/**
 * 完整还原原版备份 (restoreUnlockInternal)
 */
async function restoreUnlockInternal(options = {}) {
  const fsImpl = options.fs || fs;
  const resolved = options._preResolvedTarget || await resolveTargetBinary(options, { allowMissingTarget: true });
  if (!resolved.ok) return resolved;

  let trustedLiveCheck = options._trustedLiveCheck || null;
  if (resolved.runtimeMode === 'live') {
    if (!resolved.instanceIdentity) {
      return {
        ok: false,
        code: 'LIVE_INSTANCE_CHANGED_OR_UNRESOLVED',
        targetPath: resolved.binaryPath,
        error: '未能获取可信的运行实例身份，已拒绝还原'
      };
    }
    if (options.expectedInstanceIdentity && !matchesLiveInstanceIdentity(resolved.instanceIdentity, options.expectedInstanceIdentity)) {
      return {
        ok: false,
        code: 'LIVE_INSTANCE_CHANGED_OR_UNRESOLVED',
        targetPath: resolved.binaryPath,
        error: '检测到运行中的语言服务实例已重启或发生变化，请重新预检后再还原'
      };
    }
    if (!trustedLiveCheck) {
      trustedLiveCheck = {
        origin: options.origin,
        binaryPath: resolved.binaryPath,
        instanceIdentity: resolved.instanceIdentity
      };
    }
  }

  const { txPath } = getTargetArtifactPaths(resolved.binaryPath, options);
  const txCheck = readTxLogStrict(txPath, fsImpl);
  if (txCheck.state === 'CORRUPTED') {
    return { ok: false, code: 'CORRUPTED_TRANSACTION_LOG', targetPath: resolved.binaryPath, error: txCheck.error };
  }
  if (txCheck.state === 'OK' && txCheck.tx && !['COMMITTED', 'RECOVERED'].includes(txCheck.tx.status)) {
    return { ok: false, code: 'UNFINISHED_TRANSACTION', targetPath: resolved.binaryPath, tx: txCheck.tx, error: '该目标存在未完成的替换事务，请先执行恢复操作' };
  }
  const bakPath = `${resolved.binaryPath}.bak`;
  if (!fsImpl.existsSync(bakPath)) {
    return {
      ok: false,
      code: 'REFUSED_NO_VERIFIED_BACKUP',
      targetPath: resolved.binaryPath,
      bakPath,
      error: '未找到同目录 .bak 原版备份文件，无法执行完整原版还原'
    };
  }
  return await applyUnlockInternal({
    ...options,
    mode: '256k',
    _requireExistingBackup: true,
    _preResolvedTarget: resolved,
    _trustedLiveCheck: trustedLiveCheck
  });
}

/**
 * 3.4 故障恢复状态机 (recoverUnlockTransactionInternal)
 */
async function recoverUnlockTransactionInternal(options = {}) {
  const fsImpl = options.fs || fs;
  const resolved = options._preResolvedTarget || await resolveTargetBinary(options, { allowMissingTarget: true });
  if (!resolved.ok) return resolved;

  const targetPath = resolved.binaryPath;
  const bakPath = `${targetPath}.bak`;
  const { targetId, txPath, manifestPath } = getTargetArtifactPaths(targetPath, options);

  let trustedLiveCheck = options._trustedLiveCheck || null;
  if (resolved.runtimeMode === 'live') {
    if (!resolved.instanceIdentity) {
      return {
        ok: false,
        code: 'LIVE_INSTANCE_CHANGED_OR_UNRESOLVED',
        targetPath,
        error: '未能获取可信的运行实例身份，已拒绝执行恢复'
      };
    }
    if (options.expectedInstanceIdentity && !matchesLiveInstanceIdentity(resolved.instanceIdentity, options.expectedInstanceIdentity)) {
      return {
        ok: false,
        code: 'LIVE_INSTANCE_CHANGED_OR_UNRESOLVED',
        targetPath,
        error: '检测到运行中的语言服务实例已重启或发生变化，请刷新状态后再执行恢复'
      };
    }
    if (!trustedLiveCheck) {
      trustedLiveCheck = {
        origin: options.origin,
        binaryPath: targetPath,
        instanceIdentity: resolved.instanceIdentity
      };
    }
  }

  return await withUnlockLock(targetPath, async () => {
    const txCheck = readTxLogStrict(txPath, fsImpl);
    if (txCheck.state === 'CORRUPTED') {
      return {
        ok: false,
        code: 'CORRUPTED_TRANSACTION_LOG',
        targetPath,
        txPath,
        error: '事务日志已损坏，请检查同目录 .old 或 .bak 文件手动恢复（已保留全部现场文件）'
      };
    }

    if (trustedLiveCheck) {
      const liveRecheck = await verifyLiveInstanceUnchanged(trustedLiveCheck, {
        ...options,
        allowMissingTarget: true,
        fs: fsImpl
      });
      if (!liveRecheck.ok) {
        return liveRecheck;
      }
    }

    const tx = txCheck.tx;
    const isTerminalTx = !tx || ['COMMITTED', 'RECOVERED'].includes(tx.status);

    // 2.2 终态事务绝不回退后来丢失的目标文件
    if (isTerminalTx) {
      if (!fsImpl.existsSync(targetPath)) {
        return {
          ok: false,
          code: 'TARGET_MISSING_NO_ACTIVE_TX',
          targetPath,
          error: '目标二进制文件不存在，且无进行中的未完成替换事务'
        };
      }
      // 2.3 若事务为 COMMITTED 但写 manifest 前崩溃或失败，幂等补齐 manifest
      if (tx && tx.status === 'COMMITTED' && tx.pendingManifest) {
        const currentSha = sha256FileSync(targetPath, fsImpl);
        if (currentSha === tx.afterSha256) {
          let curM = null;
          let needSyncManifest = !fsImpl.existsSync(manifestPath);
          if (!needSyncManifest) {
            try {
              curM = JSON.parse(fsImpl.readFileSync(manifestPath, 'utf8'));
              if (
                curM.patchedSha256 !== tx.afterSha256 ||
                hasMissingRetiredOldFiles(curM.retiredOldFiles, tx.pendingManifest.retiredOldFiles)
              ) {
                needSyncManifest = true;
              }
            } catch {
              needSyncManifest = true;
            }
          }
          if (needSyncManifest) {
            const mergedManifest = {
              ...tx.pendingManifest,
              retiredOldFiles: mergeRetiredOldFiles(curM?.retiredOldFiles, tx.pendingManifest.retiredOldFiles)
            };
            try {
              writeJsonAtomicSync(manifestPath, mergedManifest, fsImpl);
            } catch (manifestErr) {
              return {
                ok: false,
                partialSuccess: true,
                committed: true,
                manifestSynced: false,
                code: 'POST_COMMIT_MANIFEST_SYNC_FAILED',
                manifestSyncError: {
                  code: manifestErr.code || 'MANIFEST_WRITE_FAILED',
                  manifestPath,
                  error: manifestErr.message
                },
                targetPath,
                targetId,
                error: `补同步状态清单失败: ${manifestErr.message}`
              };
            }
            return {
              ok: true,
              noop: true,
              manifestSynced: true,
              targetPath,
              targetId
            };
          }
        }
      }
      return {
        ok: true,
        noop: true,
        targetPath,
        targetId
      };
    }

    const finalizeRecoveredTxLog = (recoveredFrom, restoredSha256, markModified) => {
      if (markModified) {
        modifiedInCurrentProcess.add(targetId);
      }
      try {
        writeJsonAtomicSync(txPath, {
          ...tx,
          status: 'RECOVERED',
          recoveredFrom,
          recoveredAt: Date.now()
        }, fsImpl);
      } catch (txErr) {
        return {
          ok: false,
          partialSuccess: true,
          recovered: true,
          recoveredFrom,
          committed: true,
          txSynced: false,
          code: 'POST_RECOVERY_TX_LOG_SYNC_FAILED',
          txSyncError: {
            code: txErr.code || 'TX_LOG_WRITE_FAILED',
            txPath,
            error: txErr.message
          },
          targetPath,
          targetId,
          restoredSha256,
          error: `文件已恢复，事务记录待同步 (${txErr.code || txErr.message})`
        };
      }
      return {
        ok: true,
        recovered: true,
        recoveredFrom,
        committed: true,
        txSynced: true,
        targetPath,
        targetId,
        restoredSha256
      };
    };

    // 存在未完成事务 (PREPARED / MOVING_OLD / OLD_MOVED / ROLLBACK_FAILED)
    if (!fsImpl.existsSync(targetPath)) {
      // 分支 A：targetPath 不存在
      if (tx.oldPath && fsImpl.existsSync(tx.oldPath)) {
        const oldSha = sha256FileSync(tx.oldPath, fsImpl);
        if (oldSha !== tx.beforeSha256) {
          return {
            ok: false,
            code: 'OLD_FILE_HASH_MISMATCH',
            targetPath,
            recoverySourcePath: tx.oldPath,
            error: `撤离文件 (${tx.oldPath}) 哈希与事务前记录不匹配，已拒绝自动移动并保留现场`
          };
        }
        fsImpl.renameSync(tx.oldPath, targetPath);
        if (sha256FileSync(targetPath, fsImpl) !== tx.beforeSha256) {
          return {
            ok: false,
            code: 'RECOVERY_VERIFY_FAILED',
            targetPath,
            error: '从 .old 恢复后目标文件哈希复核不匹配'
          };
        }
        if (tx.stagedPath && fsImpl.existsSync(tx.stagedPath)) {
          try { fsImpl.unlinkSync(tx.stagedPath); } catch {}
        }
        return finalizeRecoveredTxLog('oldPath', tx.beforeSha256, true);
      }

      // 2.1 确定性从 .bak 恢复（仅当 sha256(bakPath) === tx.beforeSha256 时才允许作为普通事务回滚）
      if (fsImpl.existsSync(bakPath)) {
        const bakBuf = fsImpl.readFileSync(bakPath);
        const bakSha = sha256Buffer(bakBuf);
        if (bakSha === tx.beforeSha256) {
          const recoverStaged = `${targetPath}.recover.${process.pid}.${Date.now()}.exe`;
          let rfd = null;
          try {
            rfd = fsImpl.openSync(recoverStaged, 'w');
            fsImpl.writeSync(rfd, bakBuf, 0, bakBuf.length, 0);
            fsImpl.fsyncSync(rfd);
            fsImpl.closeSync(rfd);
            rfd = null;
            if (sha256FileSync(recoverStaged, fsImpl) !== tx.beforeSha256) {
              throw new Error('恢复临时文件读回哈希不匹配');
            }
            fsImpl.renameSync(recoverStaged, targetPath);
            if (sha256FileSync(targetPath, fsImpl) !== tx.beforeSha256) {
              throw new Error('恢复后目标文件哈希不匹配');
            }
          } catch (recErr) {
            if (rfd !== null) {
              try { fsImpl.closeSync(rfd); } catch {}
            }
            try { if (fsImpl.existsSync(recoverStaged)) fsImpl.unlinkSync(recoverStaged); } catch {}
            return {
              ok: false,
              code: 'RECOVERY_FROM_BAK_FAILED',
              targetPath,
              bakPath,
              error: `从备份恢复目标文件失败: ${recErr.message}`
            };
          }
          if (tx.stagedPath && fsImpl.existsSync(tx.stagedPath)) {
            try { fsImpl.unlinkSync(tx.stagedPath); } catch {}
          }
          return finalizeRecoveredTxLog('bakPath', tx.beforeSha256, true);
        }

        return {
          ok: false,
          code: 'RECOVERY_SOURCE_UNAVAILABLE',
          targetPath,
          bakPath,
          canRestoreOriginalFromBak: bakSha === tx.verifiedBakSha256,
          error: '未找到与事务前状态 (beforeSha256) 匹配的 .old 文件，且同目录 .bak 为 256K 原版而非事务前的已修改状态；已保留全部恢复材料'
        };
      }

      return {
        ok: false,
        code: 'RECOVERY_SOURCE_UNAVAILABLE',
        targetPath,
        error: '目标文件与 .old 恢复源均不存在，无法自动恢复'
      };
    }

    // 分支 B：targetPath 已存在
    const currentSha = sha256FileSync(targetPath, fsImpl);
    if (currentSha === tx.beforeSha256) {
      if (tx.stagedPath && fsImpl.existsSync(tx.stagedPath)) {
        try { fsImpl.unlinkSync(tx.stagedPath); } catch {}
      }
      return finalizeRecoveredTxLog('target_intact_before', currentSha, false);
    }

    if (currentSha === tx.afterSha256) {
      if (tx.stagedPath && fsImpl.existsSync(tx.stagedPath)) {
        try { fsImpl.unlinkSync(tx.stagedPath); } catch {}
      }
      modifiedInCurrentProcess.add(targetId);
      try {
        writeJsonAtomicSync(txPath, {
          ...tx,
          status: 'COMMITTED',
          committedAt: Date.now()
        }, fsImpl);
      } catch (txErr) {
        return {
          ok: false,
          partialSuccess: true,
          recovered: true,
          recoveredFrom: 'target_reached_after',
          committed: true,
          txSynced: false,
          manifestSynced: false,
          code: 'POST_RECOVERY_TX_LOG_SYNC_FAILED',
          txSyncError: {
            code: txErr.code || 'TX_LOG_WRITE_FAILED',
            txPath,
            error: txErr.message
          },
          targetPath,
          targetId,
          restoredSha256: currentSha,
          error: `文件已恢复，事务记录待同步 (${txErr.code || txErr.message})`
        };
      }
      if (tx.pendingManifest) {
        let curM = null;
        if (fsImpl.existsSync(manifestPath)) {
          try { curM = JSON.parse(fsImpl.readFileSync(manifestPath, 'utf8')); } catch {}
        }
        const mergedManifest = {
          ...tx.pendingManifest,
          retiredOldFiles: mergeRetiredOldFiles(curM?.retiredOldFiles, tx.pendingManifest.retiredOldFiles)
        };
        try {
          writeJsonAtomicSync(manifestPath, mergedManifest, fsImpl);
        } catch (manifestErr) {
          return {
            ok: false,
            partialSuccess: true,
            recovered: true,
            recoveredFrom: 'target_reached_after',
            committed: true,
            txSynced: true,
            manifestSynced: false,
            code: 'POST_COMMIT_MANIFEST_SYNC_FAILED',
            manifestSyncError: {
              code: manifestErr.code || 'MANIFEST_WRITE_FAILED',
              manifestPath,
              error: manifestErr.message
            },
            targetPath,
            targetId,
            restoredSha256: currentSha,
            error: `目标二进制已恢复提交，但同步状态清单失败: ${manifestErr.message}`
          };
        }
      }
      return {
        ok: true,
        recovered: true,
        recoveredFrom: 'target_reached_after',
        committed: true,
        txSynced: true,
        manifestSynced: Boolean(tx.pendingManifest),
        targetPath,
        targetId,
        restoredSha256: currentSha
      };
    }

    return {
      ok: false,
      code: 'TARGET_CHANGED_EXTERNALLY',
      targetPath,
      recoverySourcePath: tx.oldPath || null,
      currentSha256: currentSha,
      expectedBeforeSha256: tx.beforeSha256,
      expectedAfterSha256: tx.afterSha256,
      error: '目标文件已存在但哈希既不匹配事务前也不匹配事务后状态，已拒绝覆盖并保留现场'
    };
  }, options);
}

// ============================================================================
// 5. 独立执行子进程调度器与元数据索引状态缓存
// ============================================================================

const STATUS_CACHE_MAX = 8;
const statusCache = new Map();
const inflightStatusRequests = new Map();

function invalidateUnlockStatusCache(targetPath = null) {
  if (!targetPath) {
    statusCache.clear();
    return;
  }
  const key = normalizeTargetPathKey(targetPath);
  statusCache.delete(key);
}

function getFileMetaSignature(filePath, fsImpl = fs) {
  try {
    if (!fsImpl.existsSync(filePath)) return 'missing';
    const st = fsImpl.statSync(filePath);
    return `${st.size}:${st.mtimeMs}:${st.ctimeMs}`;
  } catch {
    return 'err';
  }
}

function runInUnlockWorkerSubprocess(action, payload = {}) {
  return new Promise(resolve => {
    const reqJson = JSON.stringify({ action, payload });
    const env = { ...process.env, ELECTRON_RUN_AS_NODE: '1' };
    let stdout = '';
    let stderr = '';
    let finished = false;

    const done = res => {
      if (!finished) {
        finished = true;
        resolve(res);
      }
    };

    const timer = setTimeout(() => {
      try { child.kill(); } catch {}
      done({ ok: false, code: 'WORKER_TIMEOUT', error: '解锁子进程执行超时' });
    }, payload.workerTimeoutMs || 30000);

    let child;
    try {
      child = spawn(process.execPath, [__filename, '--unlock-worker'], {
        env,
        windowsHide: true,
        stdio: ['pipe', 'pipe', 'pipe']
      });
      child.stdout.on('data', d => { stdout += d.toString('utf8'); });
      child.stderr.on('data', d => { stderr += d.toString('utf8'); });
      child.on('error', err => {
        clearTimeout(timer);
        done({ ok: false, code: 'WORKER_SPAWN_ERROR', error: err.message });
      });
      child.on('close', code => {
        clearTimeout(timer);
        const lines = stdout.trim().split(/\r?\n/).filter(Boolean);
        const lastLine = lines[lines.length - 1];
        if (lastLine) {
          try {
            return done(JSON.parse(lastLine));
          } catch {}
        }
        done({
          ok: false,
          code: 'WORKER_INVALID_OUTPUT',
          error: (stderr || stdout || `解锁子进程异常退出 (code ${code})`).trim().slice(0, 400)
        });
      });
      child.stdin.on('error', () => {});
      child.stdin.end(reqJson);
    } catch (err) {
      clearTimeout(timer);
      done({ ok: false, code: 'WORKER_SPAWN_ERROR', error: err.message });
    }
  });
}

function shouldUseDirectInProcess(options = {}) {
  if (options.inProcess === true || options.fs || options._onAfterPrepLockCreated || options._onBeforeReclaimGate || options._onAfterReclaimGateCreated || options._onAfterStaleLockMoved || options._onAfterLockAcquired || options._onAfterTxPrepared || options._onAfterOldMoved || options._onBeforeManifestWriteAfterCommit || options._resolveLiveInstance) {
    return true;
  }
  return false;
}

async function getUnlockStatus(options = {}) {
  const fsImpl = options.fs || fs;
  if (options.force === true) {
    invalidateUnlockStatusCache(options.binaryPath);
  }

  // 先快速定位目标路径并检查实时锁/事务状态与文件元数据
  const resolved = await resolveTargetBinary(options, { allowMissingTarget: true });
  if (!resolved.ok) return resolved;

  const targetPath = resolved.binaryPath;
  const bakPath = `${targetPath}.bak`;
  const cacheKey = normalizeTargetPathKey(targetPath);
  const { targetId, lockDir, txPath, manifestPath } = getTargetArtifactPaths(targetPath, options);

  // 锁与事务日志每次实时检查，绝不复用缓存
  const txCheck = readTxLogStrict(txPath, fsImpl);
  const hasActiveOrCorruptTx =
    txCheck.state === 'CORRUPTED' ||
    (txCheck.state === 'OK' && txCheck.tx && !['COMMITTED', 'RECOVERED'].includes(txCheck.tx.status));
  const targetExists = fsImpl.existsSync(targetPath);

  if (!targetExists || hasActiveOrCorruptTx) {
    statusCache.delete(cacheKey);
    if (shouldUseDirectInProcess(options) || !targetExists || txCheck.state === 'CORRUPTED') {
      return await getUnlockStatusInternal(options);
    }
    const res = await runInUnlockWorkerSubprocess('status', {
      ...options,
      runtimeMode: 'cli',
      binaryPath: targetPath
    });
    return {
      ...res,
      runtimeMode: resolved.runtimeMode,
      source: resolved.source,
      instanceIdentity: resolved.instanceIdentity || null
    };
  }

  const metaSig = [
    getFileMetaSignature(targetPath, fsImpl),
    getFileMetaSignature(bakPath, fsImpl),
    getFileMetaSignature(manifestPath, fsImpl)
  ].join('|');

  if (!options.force && statusCache.has(cacheKey)) {
    const cached = statusCache.get(cacheKey);
    if (cached.metaSig === metaSig) {
      const runtimeState =
        modifiedInCurrentProcess.has(targetId) ||
        (initialObservedDiskSha.has(targetId) && initialObservedDiskSha.get(targetId) !== cached.result.diskState?.sha256)
          ? 'pending_restart'
          : cached.result.runtimeState;
      return {
        ...cached.result,
        lockExists: fsImpl.existsSync(lockDir),
        runtimeState,
        fromCache: true
      };
    }
    statusCache.delete(cacheKey);
  }

  if (inflightStatusRequests.has(cacheKey)) {
    return await inflightStatusRequests.get(cacheKey);
  }

  const task = (async () => {
    const res = shouldUseDirectInProcess(options)
      ? await getUnlockStatusInternal(options)
      : await runInUnlockWorkerSubprocess('status', {
          ...options,
          runtimeMode: 'cli',
          binaryPath: targetPath
        });

    if (res && res.ok && res.diskState?.sha256) {
      if (!initialObservedDiskSha.has(targetId)) {
        initialObservedDiskSha.set(targetId, res.diskState.sha256);
      }
      const adjusted = {
        ...res,
        runtimeMode: resolved.runtimeMode,
        source: resolved.source,
        instanceIdentity: resolved.instanceIdentity || null,
        runtimeState:
          modifiedInCurrentProcess.has(targetId) || initialObservedDiskSha.get(targetId) !== res.diskState.sha256
            ? 'pending_restart'
            : res.runtimeState
      };
      if (statusCache.size >= STATUS_CACHE_MAX) {
        const oldestKey = statusCache.keys().next().value;
        statusCache.delete(oldestKey);
      }
      statusCache.set(cacheKey, { metaSig, result: adjusted });
      return adjusted;
    }
    return res;
  })();

  inflightStatusRequests.set(cacheKey, task);
  try {
    return await task;
  } finally {
    inflightStatusRequests.delete(cacheKey);
  }
}

async function dryRunUnlock(options = {}) {
  if (shouldUseDirectInProcess(options)) {
    return await dryRunUnlockInternal(options);
  }
  const resolved = await resolveTargetBinary(options, { allowMissingTarget: true });
  if (!resolved.ok) return resolved;
  const res = await runInUnlockWorkerSubprocess('dryRun', {
    ...options,
    runtimeMode: 'cli',
    binaryPath: resolved.binaryPath
  });
  return {
    ...res,
    runtimeMode: resolved.runtimeMode,
    source: resolved.source,
    instanceIdentity: resolved.instanceIdentity || null
  };
}

async function prepareWorkerWriteDispatch(options = {}, actionLabel = '执行操作') {
  const resolved = await resolveTargetBinary(options, { allowMissingTarget: true });
  if (!resolved.ok) return { ok: false, earlyReturn: resolved };

  if (resolved.runtimeMode === 'live') {
    if (!resolved.instanceIdentity) {
      return {
        ok: false,
        earlyReturn: {
          ok: false,
          code: 'LIVE_INSTANCE_CHANGED_OR_UNRESOLVED',
          targetPath: resolved.binaryPath,
          error: `未能获取可信的运行实例身份，已拒绝${actionLabel}`
        }
      };
    }
    if (options.expectedInstanceIdentity && !matchesLiveInstanceIdentity(resolved.instanceIdentity, options.expectedInstanceIdentity)) {
      return {
        ok: false,
        earlyReturn: {
          ok: false,
          code: 'LIVE_INSTANCE_CHANGED_OR_UNRESOLVED',
          targetPath: resolved.binaryPath,
          error: `检测到运行中的语言服务实例已重启或发生变化，请重新预检后再${actionLabel}`
        }
      };
    }
  }

  const isLive = resolved.runtimeMode === 'live';
  const workerPayload = {
    ...options,
    runtimeMode: isLive ? 'live' : 'cli',
    origin: isLive ? options.origin : undefined,
    binaryPath: resolved.binaryPath,
    _preResolvedTarget: {
      ok: true,
      binaryPath: resolved.binaryPath,
      binDir: resolved.binDir,
      runtimeMode: resolved.runtimeMode,
      source: resolved.source,
      instanceIdentity: resolved.instanceIdentity || null
    },
    _trustedLiveCheck: isLive
      ? {
          origin: options.origin,
          binaryPath: resolved.binaryPath,
          instanceIdentity: resolved.instanceIdentity
        }
      : null
  };

  return { ok: true, resolved, workerPayload };
}

async function applyUnlock(options = {}) {
  invalidateUnlockStatusCache();
  if (shouldUseDirectInProcess(options)) {
    return await applyUnlockInternal(options);
  }
  const prep = await prepareWorkerWriteDispatch(options, '应用');
  if (!prep.ok) return prep.earlyReturn;
  const { resolved, workerPayload } = prep;
  const targetId = computeTargetId(resolved.binaryPath);
  const res = await runInUnlockWorkerSubprocess('apply', workerPayload);
  if (res && (res.ok || res.committed)) {
    modifiedInCurrentProcess.add(targetId);
    invalidateUnlockStatusCache(resolved.binaryPath);
  }
  return res && typeof res === 'object'
    ? {
        ...res,
        runtimeMode: resolved.runtimeMode,
        source: resolved.source,
        instanceIdentity: res.instanceIdentity || resolved.instanceIdentity || null
      }
    : res;
}

async function restoreUnlock(options = {}) {
  invalidateUnlockStatusCache();
  if (shouldUseDirectInProcess(options)) {
    return await restoreUnlockInternal(options);
  }
  const prep = await prepareWorkerWriteDispatch(options, '还原');
  if (!prep.ok) return prep.earlyReturn;
  const { resolved, workerPayload } = prep;
  const targetId = computeTargetId(resolved.binaryPath);
  const res = await runInUnlockWorkerSubprocess('restore', workerPayload);
  if (res && (res.ok || res.committed)) {
    modifiedInCurrentProcess.add(targetId);
    invalidateUnlockStatusCache(resolved.binaryPath);
  }
  return res && typeof res === 'object'
    ? {
        ...res,
        runtimeMode: resolved.runtimeMode,
        source: resolved.source,
        instanceIdentity: res.instanceIdentity || resolved.instanceIdentity || null
      }
    : res;
}

async function recoverUnlockTransaction(options = {}) {
  invalidateUnlockStatusCache();
  if (shouldUseDirectInProcess(options)) {
    return await recoverUnlockTransactionInternal(options);
  }
  const prep = await prepareWorkerWriteDispatch(options, '执行恢复');
  if (!prep.ok) return prep.earlyReturn;
  const { resolved, workerPayload } = prep;
  const targetId = computeTargetId(resolved.binaryPath);
  const res = await runInUnlockWorkerSubprocess('recover', workerPayload);
  if (res && (res.ok || res.committed)) {
    modifiedInCurrentProcess.add(targetId);
    invalidateUnlockStatusCache(resolved.binaryPath);
  }
  return res && typeof res === 'object'
    ? {
        ...res,
        runtimeMode: resolved.runtimeMode,
        source: resolved.source,
        instanceIdentity: res.instanceIdentity || resolved.instanceIdentity || null
      }
    : res;
}

// Worker 子进程入口
if (require.main === module && process.argv.includes('--unlock-worker')) {
  let input = '';
  process.stdin.on('data', d => { input += d.toString('utf8'); });
  process.stdin.on('end', async () => {
    try {
      const { action, payload } = JSON.parse(input || '{}');
      let result;
      if (action === 'status') result = await getUnlockStatusInternal(payload);
      else if (action === 'dryRun') result = await dryRunUnlockInternal(payload);
      else if (action === 'apply') result = await applyUnlockInternal(payload);
      else if (action === 'restore') result = await restoreUnlockInternal(payload);
      else if (action === 'recover') result = await recoverUnlockTransactionInternal(payload);
      else result = { ok: false, code: 'UNKNOWN_WORKER_ACTION', error: `Unknown worker action: ${action}` };
      process.stdout.write(JSON.stringify(result) + '\n');
    } catch (err) {
      process.stdout.write(JSON.stringify({
        ok: false,
        code: err.code || 'WORKER_EXCEPTION',
        error: err.message || String(err)
      }) + '\n');
    }
  });
}

module.exports = {
  PCLNTAB_MAGIC,
  FUNC_OFFERS,
  FUNC_STORE_CW,
  FUNC_STORE_CHOICE,
  FUNC_CHECKPOINT,
  FUNC_EXP_CHECKPOINT,
  FUNC_SELECT_EXP_KEY,
  PATCH_UNLIMITED_X64,
  PRESET_MODES,
  MIN_CUSTOM_CAP_TOKENS,
  MAX_CUSTOM_CAP_TOKENS,
  PatchError,
  computeTargetId,
  resolveUnlockStateDir,
  getTargetArtifactPaths,
  normalizeTargetSpec,
  sanitizePublicUnlockOptions,
  encodeGate3aBytesX64,
  parsePeLayout,
  findTextSection,
  fileOffsetToVa,
  findPclntab,
  resolvePeGoText,
  buildFunctions,
  locateGate3a,
  locateGate3b,
  inspectBinaryBuffer,
  verifySameBuildBackup,
  buildTargetImageFromOriginalBase,
  writeJsonAtomicSync,
  readTxLogStrict,
  withUnlockLock,
  resolveBinInDir,
  resolveLiveInstanceBinary,
  resolveTargetBinary,
  getUnlockStatus,
  dryRunUnlock,
  applyUnlock,
  restoreUnlock,
  recoverUnlockTransaction,
  invalidateUnlockStatusCache
};
