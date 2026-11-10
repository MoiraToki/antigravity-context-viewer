'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');

const unlock = require('./meter-unlock');

const CLAMP_256K_X64 = Buffer.from('81fa00e80300be00e803000f42f2', 'hex');
const CLAMP_512K_X64 = Buffer.from('81fa00d00700be00d007000f42f2', 'hex');
const CLAMP_1M_X64 = Buffer.from('81fa40420f00be40420f000f42f2', 'hex');

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

/**
 * 构造离线 Windows PE32+ (x86-64) + Go .gopclntab 固件
 */
function createPeFixture(opts = {}) {
  const machine = opts.machine ?? 0x8664;
  const useJneRel32 = Boolean(opts.useJneRel32);
  const brokenClamp = Boolean(opts.brokenClamp);
  const duplicateGate3a = Boolean(opts.duplicateGate3a);
  const duplicateGate3b = Boolean(opts.duplicateGate3b);
  const duplicateTargetSymbol = Boolean(opts.duplicateTargetSymbol);
  const duplicateUnrelatedSymbol = Boolean(opts.duplicateUnrelatedSymbol);
  const gate3bAtEndTruncated = Boolean(opts.gate3bAtEndTruncated);
  const gate3bOutOfBoundsJump = Boolean(opts.gate3bOutOfBoundsJump);
  const extraNonPatchByte = opts.extraNonPatchByte ?? 0xcc;

  const data = Buffer.alloc(0x30000, 0);
  data.write('MZ', 0, 'ascii');
  data.writeUInt32LE(0x80, 0x3C);
  data.write('PE\0\0', 0x80, 'ascii');
  data.writeUInt16LE(machine, 0x84);
  data.writeUInt16LE(2, 0x86);
  data.writeUInt16LE(0xF0, 0x94);
  data.writeUInt16LE(0x20B, 0x98);
  data.writeBigUInt64LE(0x140000000n, 0xB0);

  const sections = [
    { sh: 0x188, name: '.text', va: 0x1000, ptr: 0x400, size: 0x11000 },
    { sh: 0x1B0, name: '.rdata', va: 0x20000, ptr: 0x12000, size: 0x1E000 }
  ];
  for (const s of sections) {
    const nameBuf = Buffer.alloc(8, 0);
    nameBuf.write(s.name, 0, 'ascii');
    nameBuf.copy(data, s.sh);
    data.writeUInt32LE(s.size, s.sh + 8);
    data.writeUInt32LE(s.va, s.sh + 12);
    data.writeUInt32LE(s.size, s.sh + 16);
    data.writeUInt32LE(s.ptr, s.sh + 20);
  }

  const text = 0x500;
  data.fill(0xCC, text, text + 0x10000);
  // 用于模拟不同客户端构建版本的非补丁区特征字节
  data[text + 0x10] = extraNonPatchByte;

  // Function 3 (index 3, offset 3*64 = 0xC0): utils.GetCheckpointConfig
  const cpOff = text + 3 * 64;
  if (!brokenClamp) {
    CLAMP_256K_X64.copy(data, cpOff);
    if (duplicateGate3a) {
      CLAMP_512K_X64.copy(data, cpOff + 20);
    }
  }

  // Function 4 (index 4, offset 4*64 = 0x100): config.applyFeatureProviderCheckpointOverrideConfig
  // Function 5 (index 5, offset 5*64 = 0x140): config.selectCheckpointExperimentKey
  const expOff = text + 4 * 64;
  if (gate3bAtEndTruncated) {
    // 将 call + test %al,%al 放在函数末尾 (offset 64 - 7 = 57)，使 test %al,%al 后不足 2 字节
    const callPos = expOff + 57;
    const relDisp = 64 - (57 + 5);
    data[callPos] = 0xE8;
    data.writeInt32LE(relDisp, callPos + 1);
    data[callPos + 5] = 0x84;
    data[callPos + 6] = 0xC0;
  } else {
    // 正常位置：expOff + 0 处 call Function 5 (disp = 64 - 5 = 59)
    data[expOff] = 0xE8;
    data.writeInt32LE(64 - 5, expOff + 1);
    data[expOff + 5] = 0x84;
    data[expOff + 6] = 0xC0;
    if (useJneRel32) {
      data[expOff + 7] = 0x0F;
      data[expOff + 8] = 0x85;
      data.writeInt32LE(gate3bOutOfBoundsJump ? 0x200 : 0x05, expOff + 9);
    } else {
      data[expOff + 7] = 0x75;
      data.writeInt8(gate3bOutOfBoundsJump ? 100 : 5, expOff + 8);
    }

    if (duplicateGate3b) {
      // 在同一窗口内放第二个 test %al,%al + jne
      data[expOff + 16] = 0x84;
      data[expOff + 17] = 0xC0;
      data[expOff + 18] = 0x75;
      data[expOff + 19] = 0x05;
    }
  }

  const base = 0x12000;
  const count = 1001;
  const namesOffset = 0x100;
  const tableOffset = 0x5000;
  data.writeUInt32LE(unlock.PCLNTAB_MAGIC, base);
  data[base + 6] = machine === 0xAA64 ? 4 : 1;
  data[base + 7] = 8;
  data.writeBigUInt64LE(BigInt(count), base + 8);
  data.writeBigUInt64LE(0x140001100n, base + 24);
  data.writeBigUInt64LE(BigInt(namesOffset), base + 32);
  data.writeBigUInt64LE(BigInt(tableOffset), base + 64);

  const names = [
    'pkg/' + unlock.FUNC_OFFERS,
    'pkg/' + unlock.FUNC_STORE_CW,
    'pkg/' + unlock.FUNC_STORE_CHOICE,
    'pkg/' + unlock.FUNC_CHECKPOINT,
    'pkg/' + unlock.FUNC_EXP_CHECKPOINT,
    'pkg/' + unlock.FUNC_SELECT_EXP_KEY
  ];
  if (duplicateTargetSymbol) {
    names.push('otherpkg/' + unlock.FUNC_SELECT_EXP_KEY);
  }
  if (duplicateUnrelatedSymbol) {
    names.push('pkgA/unrelated.Helper', 'pkgB/unrelated.Helper');
  }

  let namepos = 0;
  const records = (count + 1) * 8;
  for (let i = 0; i < count; i++) {
    const fnName = (i < names.length ? names[i] : `pkg/f${i}`) + '\0';
    const off = base + namesOffset + namepos;
    data.write(fnName, off, 'ascii');
    data.writeUInt32LE(i * 64, base + tableOffset + i * 8);
    data.writeUInt32LE(records + i * 8, base + tableOffset + i * 8 + 4);
    data.writeUInt32LE(i * 64, base + tableOffset + records + i * 8);
    data.writeInt32LE(namepos, base + tableOffset + records + i * 8 + 4);
    namepos += fnName.length;
  }
  data.writeUInt32LE(count * 64, base + tableOffset + count * 8);
  data.writeUInt32LE(0, base + tableOffset + count * 8 + 4);

  return data;
}

function createPeModuledataFixture(opts = {}) {
  const data = createPeFixture(opts);
  const { base, nfunc: count } = unlock.findPclntab(data);
  data.writeBigUInt64LE(0n, base + 24);
  const offsets = [0x100, 0x4000, 0x4100, 0x4200, 0x5000];
  for (let i = 0; i < 5; i++) {
    data.writeBigUInt64LE(BigInt(offsets[i]), base + 32 + i * 8);
  }
  const lengths = [0x3F00, 0x40, 0x100, 0xE00, 0x7000];
  const words = [BigInt(unlock.fileOffsetToVa(data, base))];
  for (let i = 0; i < 5; i++) {
    words.push(
      BigInt(unlock.fileOffsetToVa(data, base + offsets[i])),
      BigInt(lengths[i]),
      BigInt(lengths[i])
    );
  }
  words.push(
    words[13],
    BigInt(count + 1),
    BigInt(count + 1),
    0x140030000n,
    0x140001100n,
    BigInt(0x140001100 + count * 64),
    0x140001100n,
    BigInt(0x140001100 + count * 64)
  );
  for (let w = 0; w < 24; w++) {
    data.writeBigUInt64LE(words[w], 0x2F000 + w * 8);
  }
  return data;
}

// ============================================================================
// 1. PE32+ / moduledata 边界与符号表歧义测试
// ============================================================================

test('PE32+ 与 Go moduledata (textStart == 0) 地址映射及异常拒绝', () => {
  const pe = createPeFixture();
  assert.deepEqual(unlock.findTextSection(pe), {
    textVa: 0x140001000,
    textOff: 0x400,
    arch: 'x86-64'
  });

  const md = createPeModuledataFixture();
  assert.deepEqual(unlock.resolvePeGoText(md), {
    textVa: 0x140001100,
    textOff: 0x500,
    textEnd: 0x11400
  });

  // 缺失 moduledata 拒绝
  const noMd = createPeFixture();
  noMd.writeBigUInt64LE(0n, 0x12000 + 24);
  assert.throws(() => unlock.resolvePeGoText(noMd), /expected one validated PE moduledata, found 0/);

  // 2 处歧义 moduledata 拒绝
  const dupMd = createPeModuledataFixture();
  dupMd.copy(dupMd, 0x2F100, 0x2F000, 0x2F0C0);
  assert.throws(() => unlock.resolvePeGoText(dupMd), /found 2/);

  // 非零但越界的 textStart 不回退
  const badHeader = createPeModuledataFixture();
  badHeader.writeBigUInt64LE(1n, 0x12000 + 24);
  assert.throws(() => unlock.resolvePeGoText(badHeader), /outside/);

  // 非 x64 (ARM64) 拒绝
  const armPe = createPeFixture({ machine: 0xAA64 });
  const armRes = unlock.inspectBinaryBuffer(armPe);
  assert.equal(armRes.ok, false);
  assert.equal(armRes.code, 'UNSUPPORTED_ARCH');
});

test('目标符号重名歧义拒绝，无关函数重名不误拒', () => {
  const dupTarget = createPeFixture({ duplicateTargetSymbol: true });
  const res1 = unlock.inspectBinaryBuffer(dupTarget);
  assert.equal(res1.ok, false);
  assert.equal(res1.code, 'AMBIGUOUS_SYMBOL');
  assert.match(res1.error, /selectCheckpointExperimentKey/);

  const dupUnrelated = createPeFixture({ duplicateUnrelatedSymbol: true });
  const res2 = unlock.inspectBinaryBuffer(dupUnrelated);
  assert.equal(res2.ok, true);
  assert.equal(res2.isUnpatchedOriginal, true);
});

// ============================================================================
// 2. Gate 3A / Gate 3B 唯一性、越界、部分 NOP 损坏与无备份只读测试
// ============================================================================

test('Gate 3A 与 Gate 3B 多候选歧义、末尾截断与越界跳转全部安全拒绝', () => {
  const dup3a = createPeFixture({ duplicateGate3a: true });
  assert.equal(unlock.inspectBinaryBuffer(dup3a).code, 'GATE3A_AMBIGUOUS');

  const dup3b = createPeFixture({ duplicateGate3b: true });
  assert.equal(unlock.inspectBinaryBuffer(dup3b).code, 'GATE3B_AMBIGUOUS');

  const trunc3b = createPeFixture({ gate3bAtEndTruncated: true });
  assert.equal(unlock.inspectBinaryBuffer(trunc3b).code, 'GATE3B_TRUNCATED');

  const oobRel8 = createPeFixture({ gate3bOutOfBoundsJump: true });
  assert.equal(unlock.inspectBinaryBuffer(oobRel8).code, 'GATE3B_INVALID_TARGET');

  const oobRel32 = createPeFixture({ useJneRel32: true, gate3bOutOfBoundsJump: true });
  assert.equal(unlock.inspectBinaryBuffer(oobRel32).code, 'GATE3B_INVALID_TARGET');
});

test('有同构建备份时识别 6 字节跳转的部分 NOP 损坏；无备份时将 90 90 标记为 UNVERIFIED_PATCHED 只读', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-unlock-gate3b-'));
  const stateDir = path.join(tmpDir, 'state');
  try {
    const orig6 = createPeFixture({ useJneRel32: true });
    const partialNop6 = Buffer.from(orig6);
    // 将 Gate 3A 改为 512K，但把 6 字节 jne rel32 (0f 85 05 00 00 00) 仅前 2 字节改为 90 90
    CLAMP_512K_X64.copy(partialNop6, 0x500 + 3 * 64);
    partialNop6[0x500 + 4 * 64 + 7] = 0x90;
    partialNop6[0x500 + 4 * 64 + 8] = 0x90;

    // 1. 有同构建备份时：verifySameBuildBackup 必须识别为 CORRUPTED_GATE3B
    const verifyRes = unlock.verifySameBuildBackup(partialNop6, orig6);
    assert.equal(verifyRes.valid, false);
    assert.equal(verifyRes.code, 'CORRUPTED_GATE3B');

    // 2. 无备份时：静态检测为 UNVERIFIED_PATCHED，状态查询只读可看，但预检/应用/还原全部拒绝
    const binPath = path.join(tmpDir, 'language_server.exe');
    fs.writeFileSync(binPath, partialNop6);

    const st = await unlock.getUnlockStatus({
      runtimeMode: 'cli',
      binaryPath: binPath,
      _testStateDir: stateDir,
      inProcess: true
    });
    assert.equal(st.ok, true);
    assert.equal(st.status, 'unverified_external_patch');
    assert.equal(st.canWrite, false);
    assert.equal(st.canRestore, false);

    const dryRes = await unlock.dryRunUnlock({
      runtimeMode: 'cli',
      binaryPath: binPath,
      mode: '1m',
      _testStateDir: stateDir,
      inProcess: true
    });
    assert.equal(dryRes.ok, false);
    assert.equal(dryRes.code, 'REFUSED_NO_VERIFIED_BACKUP');

    const applyRes = await unlock.applyUnlock({
      runtimeMode: 'cli',
      binaryPath: binPath,
      mode: '1m',
      _testStateDir: stateDir,
      inProcess: true
    });
    assert.equal(applyRes.ok, false);
    assert.equal(applyRes.code, 'REFUSED_NO_VERIFIED_BACKUP');
    assert.deepEqual(fs.readFileSync(binPath), partialNop6);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

// ============================================================================
// 3. 多档位转换、混合状态修复、Dry-Run 纯只读与 256K 完整还原测试
// ============================================================================

test('Dry-Run 严格只读，多档位 (256K/512K/1M/自定义/取消封顶) 互转、混合状态修复与 256K 完整字节还原', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-unlock-tiers-'));
  const stateDir = path.join(tmpDir, 'state');
  try {
    const binPath = path.join(tmpDir, 'language_server.exe');
    const original = createPeModuledataFixture({ useJneRel32: true });
    const originalSha = sha256(original);
    fs.writeFileSync(binPath, original);

    // 1. Dry-Run 严格只读：不创建 stateDir、不创建 .bak、不修改目标文件
    const dry512 = await unlock.dryRunUnlock({
      runtimeMode: 'cli',
      binaryPath: binPath,
      mode: '512k',
      _testStateDir: stateDir,
      inProcess: true
    });
    assert.equal(dry512.ok, true);
    assert.equal(dry512.changed, true);
    assert.equal(dry512.beforeSha256, originalSha);
    assert.equal(fs.existsSync(binPath + '.bak'), false, 'Dry-Run 绝不能创建 .bak');
    assert.equal(fs.existsSync(stateDir), false, 'Dry-Run 绝不能创建 stateDir 或任何日志');

    // 2. 应用 512K -> 自动建立 .bak 并修改 Gate 3A (512K) 与 Gate 3B (6x NOP)
    const app512 = await unlock.applyUnlock({
      runtimeMode: 'cli',
      binaryPath: binPath,
      mode: '512k',
      expectedBeforeSha256: dry512.beforeSha256,
      _testStateDir: stateDir,
      inProcess: true
    });
    assert.equal(app512.ok, true);
    assert.equal(app512.changed, true);
    assert.equal(app512.afterSha256, dry512.afterSha256);
    assert.equal(fs.existsSync(binPath + '.bak'), true);
    assert.equal(sha256(fs.readFileSync(binPath + '.bak')), originalSha);
    assert.deepEqual(fs.readFileSync(binPath).subarray(0x500 + 3 * 64, 0x500 + 3 * 64 + 14), CLAMP_512K_X64);
    assert.deepEqual(fs.readFileSync(binPath).subarray(0x500 + 4 * 64 + 7, 0x500 + 4 * 64 + 13), Buffer.alloc(6, 0x90));

    // 重复应用 512K 幂等返回 changed: false
    const repeat512 = await unlock.applyUnlock({
      runtimeMode: 'cli',
      binaryPath: binPath,
      mode: '512k',
      _testStateDir: stateDir,
      inProcess: true
    });
    assert.equal(repeat512.ok, true);
    assert.equal(repeat512.changed, false);

    // 3. 切换至 1M (1,000,000) -> 自定义 768K -> 取消本地封顶 (unlimited)
    const app1m = await unlock.applyUnlock({
      runtimeMode: 'cli',
      binaryPath: binPath,
      mode: '1m',
      _testStateDir: stateDir,
      inProcess: true
    });
    assert.equal(app1m.ok, true);
    assert.equal(app1m.appliedSpec.capTokens, 1000000);
    assert.deepEqual(fs.readFileSync(binPath).subarray(0x500 + 3 * 64, 0x500 + 3 * 64 + 14), CLAMP_1M_X64);

    const appCustom = await unlock.applyUnlock({
      runtimeMode: 'cli',
      binaryPath: binPath,
      mode: 'custom',
      customK: 768,
      _testStateDir: stateDir,
      inProcess: true
    });
    assert.equal(appCustom.ok, true);
    assert.equal(appCustom.appliedSpec.capTokens, 768000);

    const appUnlim = await unlock.applyUnlock({
      runtimeMode: 'cli',
      binaryPath: binPath,
      mode: 'unlimited',
      _testStateDir: stateDir,
      inProcess: true
    });
    assert.equal(appUnlim.ok, true);
    assert.equal(appUnlim.appliedSpec.mode, 'unlimited');
    assert.deepEqual(
      fs.readFileSync(binPath).subarray(0x500 + 3 * 64, 0x500 + 3 * 64 + 14),
      unlock.PATCH_UNLIMITED_X64
    );

    // 4. 构造混合状态（Gate 3A 写回 256K，但 Gate 3B 仍为 6x NOP），验证 applyUnlock('256k') 按全文件比对完整修复
    const mixedBuf = fs.readFileSync(binPath);
    CLAMP_256K_X64.copy(mixedBuf, 0x500 + 3 * 64);
    fs.writeFileSync(binPath, mixedBuf);
    assert.notEqual(sha256(fs.readFileSync(binPath)), originalSha);

    const heal256 = await unlock.applyUnlock({
      runtimeMode: 'cli',
      binaryPath: binPath,
      mode: '256k',
      _testStateDir: stateDir,
      inProcess: true
    });
    assert.equal(heal256.ok, true);
    assert.equal(heal256.changed, true, '混合状态下切回 256k 必须识别与原版字节差异并完整修复 Gate 3B');
    assert.equal(sha256(fs.readFileSync(binPath)), originalSha);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

// ============================================================================
// 4. 跨版本备份防误盖 (verifySameBuildBackup) 测试
// ============================================================================

test('客户端升级后被外部修改时拒绝旧版本 .bak 覆盖；客户端升级为未修改 256K 原版时自动归档旧备份并刷新 .bak', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-unlock-version-'));
  const stateDir = path.join(tmpDir, 'state');
  try {
    const binPath = path.join(tmpDir, 'language_server.exe');
    const v1Orig = createPeFixture({ extraNonPatchByte: 0x11 });
    const v2Orig = createPeFixture({ extraNonPatchByte: 0x22 });

    // 先在 v1 上应用 512K 产生 v1 的 .bak 和 manifest
    fs.writeFileSync(binPath, v1Orig);
    const r1 = await unlock.applyUnlock({
      runtimeMode: 'cli',
      binaryPath: binPath,
      mode: '512k',
      _testStateDir: stateDir,
      inProcess: true
    });
    assert.equal(r1.ok, true);
    assert.equal(sha256(fs.readFileSync(binPath + '.bak')), sha256(v1Orig));

    // 场景 A：模拟客户端升级到 v2，且被外部工具打上 512K 补丁，而目录下仍留着 v1 的 .bak
    const v2External512 = Buffer.from(v2Orig);
    CLAMP_512K_X64.copy(v2External512, 0x500 + 3 * 64);
    v2External512[0x500 + 4 * 64 + 7] = 0x90;
    v2External512[0x500 + 4 * 64 + 8] = 0x90;
    fs.writeFileSync(binPath, v2External512);

    const restoreAttempt = await unlock.restoreUnlock({
      runtimeMode: 'cli',
      binaryPath: binPath,
      _testStateDir: stateDir,
      inProcess: true
    });
    assert.equal(restoreAttempt.ok, false, '严禁将旧版本 v1 的 .bak 恢复到 v2 二进制上');
    assert.equal(restoreAttempt.code, 'REFUSED_NO_VERIFIED_BACKUP');
    assert.equal(sha256(fs.readFileSync(binPath)), sha256(v2External512));

    // 场景 B：客户端正常升级为未修改的 v2 原版 (256K)，此时应用 512K 应自动刷新 .bak 为 v2 原版
    fs.writeFileSync(binPath, v2Orig);
    const r2 = await unlock.applyUnlock({
      runtimeMode: 'cli',
      binaryPath: binPath,
      mode: '512k',
      _testStateDir: stateDir,
      inProcess: true
    });
    assert.equal(r2.ok, true);
    assert.equal(sha256(fs.readFileSync(binPath + '.bak')), sha256(v2Orig), '.bak 必须已刷新为 v2 原版');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

// ============================================================================
// 5. 跨进程锁、门禁分流与多阶段故障注入恢复测试
// ============================================================================

test('锁协议 1.1 & 1.4：正常释放导致 ENOENT 时自动重试建锁；释放锁遇到瞬时 EPERM 重试及释放失败保留 committed', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-unlock-lock-retry-'));
  const stateDir = path.join(tmpDir, 'state');
  try {
    const targetPath = path.join(tmpDir, 'language_server.exe');
    fs.writeFileSync(targetPath, createPeFixture());
    const { lockDir } = unlock.getTargetArtifactPaths(targetPath, { _testStateDir: stateDir });

    // 1.1 模拟第一次建锁时 lockDir 存在，但在读取 owner.json 前被上一持锁者正常移走
    fs.mkdirSync(lockDir, { recursive: true });
    let interceptedOnce = false;
    const customFs1 = Object.create(fs);
    customFs1.readFileSync = function (p, ...args) {
      if (!interceptedOnce && String(p).endsWith('owner.json') && String(p).includes('.lock.d')) {
        interceptedOnce = true;
        fs.rmdirSync(lockDir);
        const err = new Error('ENOENT');
        err.code = 'ENOENT';
        throw err;
      }
      return fs.readFileSync(p, ...args);
    };

    const res1 = await unlock.withUnlockLock(targetPath, async () => {
      return { ok: true, insideLock: true };
    }, { _testStateDir: stateDir, fs: customFs1 });
    assert.equal(res1.ok, true);
    assert.equal(res1.insideLock, true);

    // 1.4 模拟释放锁时前 2 次 renameSync(lockDir, relDir) 抛 EPERM，第 3 次成功
    let relFailCount = 0;
    const customFs2 = Object.create(fs);
    customFs2.renameSync = function (oldP, newP) {
      if (String(oldP) === lockDir && String(newP).includes('.rel-') && relFailCount < 2) {
        relFailCount++;
        const err = new Error('transient EPERM');
        err.code = 'EPERM';
        throw err;
      }
      return fs.renameSync(oldP, newP);
    };

    const res2 = await unlock.withUnlockLock(targetPath, async () => {
      return { ok: true, committed: true };
    }, { _testStateDir: stateDir, fs: customFs2 });
    assert.equal(res2.ok, true);
    assert.equal(relFailCount, 2);
    assert.equal(fs.existsSync(lockDir), false);

    // 1.4b 模拟释放锁 5 次全部失败：返回 lockReleaseError 但保留 committed: true
    const customFs3 = Object.create(fs);
    customFs3.renameSync = function (oldP, newP) {
      if (String(oldP) === lockDir && String(newP).includes('.rel-')) {
        const err = new Error('persistent EPERM');
        err.code = 'EPERM';
        throw err;
      }
      return fs.renameSync(oldP, newP);
    };

    const res3 = await unlock.withUnlockLock(targetPath, async () => {
      return { ok: true, committed: true };
    }, { _testStateDir: stateDir, fs: customFs3 });
    assert.equal(res3.committed, true, '释放锁失败绝不能掩盖业务已提交状态');
    assert.equal(res3.lockReleaseError.code, 'LOCK_RELEASE_FAILED');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('锁协议 1.2：两进程同时回收同一死锁竞态测试 & 回收间隙被第三方进程 C 抢占测试', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-unlock-reclaim-race-'));
  const stateDir = path.join(tmpDir, 'state');
  try {
    const targetPath = path.join(tmpDir, 'language_server.exe');
    fs.writeFileSync(targetPath, createPeFixture());
    const { lockDir } = unlock.getTargetArtifactPaths(targetPath, { _testStateDir: stateDir });

    // 预置死进程锁 T0 (PID 99999999)
    fs.mkdirSync(lockDir, { recursive: true });
    fs.writeFileSync(path.join(lockDir, 'owner.json'), JSON.stringify({
      pid: 99999999,
      token: 'dead-token-t0',
      targetId: unlock.computeTargetId(targetPath),
      targetPath,
      createdAt: Date.now() - 10000
    }));

    // 让 B 先读到死锁 T0 并暂停在创建门禁前；此时 A 完成全部回收并进入临界区，验证 B 唤醒后被门禁拦截
    let bPausedResolve;
    const bPausedPromise = new Promise(r => { bPausedResolve = r; });
    let allowBProceedResolve;
    const allowBProceedPromise = new Promise(r => { allowBProceedResolve = r; });

    const taskB = unlock.withUnlockLock(targetPath, async () => {
      return { ok: true, worker: 'B' };
    }, {
      _testStateDir: stateDir,
      _onBeforeReclaimGate: async () => {
        bPausedResolve();
        await allowBProceedPromise;
      }
    });

    await bPausedPromise;

    // 此时 A 执行回收并持锁，在 A 持锁期间放行 B！
    const resA = await unlock.withUnlockLock(targetPath, async () => {
      allowBProceedResolve();
      const bRes = await taskB;
      assert.equal(bRes.ok, false);
      assert.equal(bRes.code, 'LOCKED_BY_OTHER_PROCESS', 'B 必须被门禁拦截，绝不能移走 A 的新锁');
      // 确认此时 lockDir 仍然完好属于 A
      const curOwner = JSON.parse(fs.readFileSync(path.join(lockDir, 'owner.json'), 'utf8'));
      assert.notEqual(curOwner.token, 'dead-token-t0');
      return { ok: true, worker: 'A', bRes };
    }, { _testStateDir: stateDir });

    assert.equal(resA.ok, true);
    assert.equal(resA.worker, 'A');

    // 测试 1.2b：回收者移走旧锁 T1 后、移入新锁前，第三方进程 C 抢先建锁成功
    fs.mkdirSync(lockDir, { recursive: true });
    fs.writeFileSync(path.join(lockDir, 'owner.json'), JSON.stringify({
      pid: 99999998,
      token: 'dead-token-t1',
      targetId: unlock.computeTargetId(targetPath),
      targetPath,
      createdAt: Date.now() - 10000
    }));

    const resReclaimerPreempted = await unlock.withUnlockLock(targetPath, async () => {
      return { ok: true };
    }, {
      _testStateDir: stateDir,
      _onAfterStaleLockMoved: async ({ lockDir: lDir }) => {
        // 模拟第三方存活进程 C 在此微秒级空窗合法建锁
        fs.mkdirSync(lDir, { recursive: true });
        fs.writeFileSync(path.join(lDir, 'owner.json'), JSON.stringify({
          pid: process.pid,
          token: 'third-party-c-token',
          targetId: unlock.computeTargetId(targetPath),
          targetPath,
          createdAt: Date.now()
        }));
      }
    });

    assert.equal(resReclaimerPreempted.ok, false);
    assert.equal(resReclaimerPreempted.code, 'LOCKED_BY_OTHER_PROCESS');
    // 验证 C 的锁毫发无损
    const cOwner = JSON.parse(fs.readFileSync(path.join(lockDir, 'owner.json'), 'utf8'));
    assert.equal(cOwner.token, 'third-party-c-token');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('锁协议：回收者二次崩溃返回 RECLAIM_INTERRUPTED & 回收者移走旧锁失败持久化 FAILED 状态', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-unlock-reclaim-fail-'));
  const stateDir = path.join(tmpDir, 'state');
  try {
    const targetPath = path.join(tmpDir, 'language_server.exe');
    fs.writeFileSync(targetPath, createPeFixture());
    const { targetId, lockDir } = unlock.getTargetArtifactPaths(targetPath, { _testStateDir: stateDir });

    // 1. 模拟回收者创建门禁 (status: RECLAIMING, reclaimerPid: 99999997 已退出) 后在移走旧锁 T2 前崩溃
    fs.mkdirSync(lockDir, { recursive: true });
    fs.writeFileSync(path.join(lockDir, 'owner.json'), JSON.stringify({
      pid: 99999996,
      token: 'dead-token-t2',
      targetId,
      targetPath,
      createdAt: Date.now() - 20000
    }));
    const gateT2 = path.join(stateDir, `unlock-${targetId}.reclaim-dead-token-t2.gate.d`);
    fs.mkdirSync(gateT2, { recursive: true });
    fs.writeFileSync(path.join(gateT2, 'reclaimer.json'), JSON.stringify({
      status: 'RECLAIMING',
      reclaimerPid: 99999997,
      reclaimerToken: 'dead-reclaimer-a',
      staleToken: 'dead-token-t2',
      createdAt: Date.now() - 10000
    }));

    const resInterrupted = await unlock.withUnlockLock(targetPath, async () => ({ ok: true }), {
      _testStateDir: stateDir
    });
    assert.equal(resInterrupted.ok, false);
    assert.equal(resInterrupted.code, 'RECLAIM_INTERRUPTED');
    assert.equal(fs.existsSync(lockDir), true, '现场必须保留');

    // 2. 模拟回收者创建门禁后移走旧锁 T3 抛出 EPERM，验证持久化 status: FAILED，且后续调用即使 PID 存活仍报需要人工处理
    fs.writeFileSync(path.join(lockDir, 'owner.json'), JSON.stringify({
      pid: 99999995,
      token: 'dead-token-t3',
      targetId,
      targetPath,
      createdAt: Date.now() - 20000
    }));

    const customFsFailMove = Object.create(fs);
    customFsFailMove.renameSync = function (oldP, newP) {
      if (String(oldP) === lockDir && String(newP).includes('.stale-dead-token-t3')) {
        const err = new Error('simulated EPERM on stale lock move');
        err.code = 'EPERM';
        throw err;
      }
      return fs.renameSync(oldP, newP);
    };

    const resMoveFail1 = await unlock.withUnlockLock(targetPath, async () => ({ ok: true }), {
      _testStateDir: stateDir,
      fs: customFsFailMove
    });
    assert.equal(resMoveFail1.ok, false);
    assert.equal(resMoveFail1.code, 'RECLAIM_FAILED_MANUAL_INTERVENTION_REQUIRED');

    // 第二次调用（此时前次回收者 PID 即当前 process.pid 仍存活！）：必须因为 status === 'FAILED' 继续返回 RECLAIM_FAILED_MANUAL_INTERVENTION_REQUIRED
    const resMoveFail2 = await unlock.withUnlockLock(targetPath, async () => ({ ok: true }), {
      _testStateDir: stateDir
    });
    assert.equal(resMoveFail2.ok, false);
    assert.equal(resMoveFail2.code, 'RECLAIM_FAILED_MANUAL_INTERVENTION_REQUIRED');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('锁协议：创建锁后暂停超过 2 秒绝不被误抢锁 & 损坏锁目录返回 CORRUPTED_LOCK_FILE', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-unlock-pause-'));
  const stateDir = path.join(tmpDir, 'state');
  try {
    const targetPath = path.join(tmpDir, 'language_server.exe');
    fs.writeFileSync(targetPath, createPeFixture());
    const { lockDir } = unlock.getTargetArtifactPaths(targetPath, { _testStateDir: stateDir });

    // 1. 进程 A 获取锁后暂停 2.1 秒，期间进程 B 尝试获取锁
    let holderAcquiredResolve;
    const holderAcquired = new Promise(r => { holderAcquiredResolve = r; });

    const holderTask = unlock.withUnlockLock(targetPath, async () => {
      holderAcquiredResolve();
      await new Promise(r => setTimeout(r, 2100));
      return { ok: true, held: true };
    }, { _testStateDir: stateDir });

    await holderAcquired;
    await new Promise(r => setTimeout(r, 1200));

    const contenderRes = await unlock.withUnlockLock(targetPath, async () => ({ ok: true }), {
      _testStateDir: stateDir
    });
    assert.equal(contenderRes.ok, false);
    assert.equal(contenderRes.code, 'LOCKED_BY_OTHER_PROCESS');

    const holderFinal = await holderTask;
    assert.equal(holderFinal.ok, true);
    assert.equal(fs.existsSync(lockDir), false);

    // 2. 构造损坏的空 lockDir（无 owner.json），验证返回 CORRUPTED_LOCK_FILE 且保留现场
    fs.mkdirSync(lockDir, { recursive: true });
    const corruptRes = await unlock.withUnlockLock(targetPath, async () => ({ ok: true }), {
      _testStateDir: stateDir
    });
    assert.equal(corruptRes.ok, false);
    assert.equal(corruptRes.code, 'CORRUPTED_LOCK_FILE');
    assert.equal(fs.existsSync(lockDir), true);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('真实子进程持锁并在 OLD_MOVED 阶段崩溃退出，父进程调用 recoverUnlockTransaction 自动回收陈旧锁并恢复文件', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-unlock-child-crash-'));
  const stateDir = path.join(tmpDir, 'state');
  try {
    // 测试兼容文件名 language_server_windows_x64.exe 在 OLD_MOVED 缺失时的反查与恢复
    const binDir = path.join(tmpDir, 'resources', 'bin');
    fs.mkdirSync(binDir, { recursive: true });
    const targetPath = path.join(binDir, 'language_server_windows_x64.exe');
    const original = createPeFixture();
    const originalSha = sha256(original);
    fs.writeFileSync(targetPath, original);

    // 启动真实子进程：获取锁、将 targetPath 移至 .old、写好 OLD_MOVED 事务日志后直接 process.exit(1)（留下子进程死锁与缺失的 targetPath）
    const childScript = `
      const fs = require('fs');
      const path = require('path');
      const unlock = require(${JSON.stringify(path.resolve(__dirname, 'meter-unlock.js'))});
      const targetPath = ${JSON.stringify(targetPath)};
      const stateDir = ${JSON.stringify(stateDir)};
      unlock.applyUnlock({
        runtimeMode: 'cli',
        binaryPath: targetPath,
        mode: '512k',
        _testStateDir: stateDir,
        _forceHotRename: true,
        inProcess: true,
        _onAfterOldMoved: async () => {
          process.exit(99);
        }
      });
    `;

    const exitCode = await new Promise(resolve => {
      const child = spawn(process.execPath, ['-e', childScript], { stdio: 'ignore', windowsHide: true });
      child.on('close', code => resolve(code));
    });
    assert.equal(exitCode, 99);
    assert.equal(fs.existsSync(targetPath), false, '崩溃后目标文件处于缺失状态');

    // 验证不传 binaryPath（仅通过 Electron 模式绑定 resources 目录）时，getUnlockStatus 能通过事务反查定位到 language_server_windows_x64.exe 且保持只读
    const stBefore = await unlock.getUnlockStatus({
      runtimeMode: 'electron',
      _testResourcesPath: path.join(tmpDir, 'resources'),
      _testStateDir: stateDir,
      inProcess: true
    });
    assert.equal(stBefore.ok, true);
    assert.equal(stBefore.status, 'interrupted_transaction');
    assert.equal(stBefore.targetPath, targetPath);
    assert.equal(stBefore.needsRecovery, true);

    // 验证未恢复前发起新的 applyUnlock 会被 UNFINISHED_TRANSACTION 拦截
    const blockedApply = await unlock.applyUnlock({
      runtimeMode: 'cli',
      binaryPath: targetPath,
      mode: '512k',
      _testStateDir: stateDir,
      inProcess: true
    });
    assert.equal(blockedApply.ok, false);
    assert.equal(blockedApply.code, 'UNFINISHED_TRANSACTION');

    // 执行恢复：自动回收死掉的子进程锁，并将 .old 恢复回 language_server_windows_x64.exe
    const recRes = await unlock.recoverUnlockTransaction({
      runtimeMode: 'electron',
      _testResourcesPath: path.join(tmpDir, 'resources'),
      _testStateDir: stateDir,
      inProcess: true
    });
    assert.equal(recRes.ok, true);
    assert.equal(recRes.recovered, true);
    assert.equal(recRes.recoveredFrom, 'oldPath');
    assert.equal(fs.existsSync(targetPath), true);
    assert.equal(sha256(fs.readFileSync(targetPath)), originalSha);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('事务恢复边界：损坏日志熔断、从 512K 崩溃缺失 oldPath 时拒绝用 256K .bak 冒充、终态后目标丢失报错、COMMITTED 幂等补写 manifest', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-unlock-tx-edges-'));
  const stateDir = path.join(tmpDir, 'state');
  try {
    const targetPath = path.join(tmpDir, 'language_server.exe');
    const original = createPeFixture();
    const originalSha = sha256(original);
    fs.writeFileSync(targetPath, original);
    const { txPath, manifestPath } = unlock.getTargetArtifactPaths(targetPath, { _testStateDir: stateDir });

    // 1. 事务日志损坏熔断测试
    fs.mkdirSync(stateDir, { recursive: true });
    fs.writeFileSync(txPath, '{broken json', 'utf8');
    const corruptApply = await unlock.applyUnlock({
      runtimeMode: 'cli',
      binaryPath: targetPath,
      mode: '512k',
      _testStateDir: stateDir,
      inProcess: true
    });
    assert.equal(corruptApply.ok, false);
    assert.equal(corruptApply.code, 'CORRUPTED_TRANSACTION_LOG');

    const corruptRec = await unlock.recoverUnlockTransaction({
      runtimeMode: 'cli',
      binaryPath: targetPath,
      _testStateDir: stateDir,
      inProcess: true
    });
    assert.equal(corruptRec.ok, false);
    assert.equal(corruptRec.code, 'CORRUPTED_TRANSACTION_LOG');
    fs.unlinkSync(txPath);

    // 2. 先打上 512K 补丁，然后在 512K -> 1M 过程中模拟 OLD_MOVED 中断且 oldPath 丢失
    // 此时 beforeSha256 是 512K，而 .bak 是 256K：必须返回 RECOVERY_SOURCE_UNAVAILABLE，绝不静默恢复为 256K
    await unlock.applyUnlock({
      runtimeMode: 'cli',
      binaryPath: targetPath,
      mode: '512k',
      _testStateDir: stateDir,
      inProcess: true
    });

    await unlock.applyUnlock({
      runtimeMode: 'cli',
      binaryPath: targetPath,
      mode: '1m',
      _testStateDir: stateDir,
      _forceHotRename: true,
      inProcess: true,
      _onAfterOldMoved: async ({ oldPath }) => {
        fs.unlinkSync(oldPath);
        throw new Error('simulated crash after oldPath deleted');
      }
    }).catch(() => {});

    const recUnavail = await unlock.recoverUnlockTransaction({
      runtimeMode: 'cli',
      binaryPath: targetPath,
      _testStateDir: stateDir,
      inProcess: true
    });
    assert.equal(recUnavail.ok, false);
    assert.equal(recUnavail.code, 'RECOVERY_SOURCE_UNAVAILABLE');
    assert.equal(recUnavail.canRestoreOriginalFromBak, true);

    // 3. 若事务前本身就是 256K 原版 (beforeSha256 === sha256(bak))，oldPath 丢失时允许通过临时文件从 .bak 恢复
    fs.unlinkSync(txPath);
    fs.writeFileSync(targetPath, original);
    await unlock.applyUnlock({
      runtimeMode: 'cli',
      binaryPath: targetPath,
      mode: '512k',
      _testStateDir: stateDir,
      _forceHotRename: true,
      inProcess: true,
      _onAfterOldMoved: async ({ oldPath }) => {
        fs.unlinkSync(oldPath);
        throw new Error('simulated crash from 256K with missing oldPath');
      }
    }).catch(() => {});

    const recFromBak = await unlock.recoverUnlockTransaction({
      runtimeMode: 'cli',
      binaryPath: targetPath,
      _testStateDir: stateDir,
      inProcess: true
    });
    assert.equal(recFromBak.ok, true);
    assert.equal(recFromBak.recoveredFrom, 'bakPath');
    assert.equal(sha256(fs.readFileSync(targetPath)), originalSha);

    // 4. 事务已 COMMITTED（但写 manifest 前崩溃），验证 recoverUnlockTransaction 幂等补写 manifest
    if (fs.existsSync(manifestPath)) fs.unlinkSync(manifestPath);
    await unlock.applyUnlock({
      runtimeMode: 'cli',
      binaryPath: targetPath,
      mode: '512k',
      _testStateDir: stateDir,
      inProcess: true,
      _onBeforeManifestWriteAfterCommit: async () => {
        throw new Error('crash right before writing manifest');
      }
    }).catch(() => {});
    assert.equal(fs.existsSync(manifestPath), false);

    const syncManifestRes = await unlock.recoverUnlockTransaction({
      runtimeMode: 'cli',
      binaryPath: targetPath,
      _testStateDir: stateDir,
      inProcess: true
    });
    assert.equal(syncManifestRes.ok, true);
    assert.equal(syncManifestRes.manifestSynced, true);
    assert.equal(fs.existsSync(manifestPath), true);

    // 5. 终态事务下后续 targetPath 被外部删除，调用 recoverUnlockTransaction 必须返回 TARGET_MISSING_NO_ACTIVE_TX
    fs.unlinkSync(targetPath);
    const missingNoTx = await unlock.recoverUnlockTransaction({
      runtimeMode: 'cli',
      binaryPath: targetPath,
      _testStateDir: stateDir,
      inProcess: true
    });
    assert.equal(missingNoTx.ok, false);
    assert.equal(missingNoTx.code, 'TARGET_MISSING_NO_ACTIVE_TX');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

// ============================================================================
// 6. 有据清理 (retiredOldFiles)、运行模式路径隔离与独立子进程 Worker 测试
// ============================================================================

test('仅清理 manifest.retiredOldFiles 中登记且哈希匹配的旧文件，且独立 Worker 子进程正常执行全流程', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-unlock-worker-clean-'));
  const stateDir = path.join(tmpDir, 'state');
  try {
    const targetPath = path.join(tmpDir, 'language_server.exe');
    const original = createPeFixture();
    fs.writeFileSync(targetPath, original);

    // 在同目录放一个未登记的未知 .old.untracked 文件，验证绝不会被误删
    const untrackedOld = `${targetPath}.old.untracked`;
    fs.writeFileSync(untrackedOld, 'do-not-delete');

    // 第一次热重命名 (256K -> 512K) 产生一个登记的 .old 文件
    const r1 = await unlock.applyUnlock({
      runtimeMode: 'cli',
      binaryPath: targetPath,
      mode: '512k',
      _testStateDir: stateDir,
      _forceHotRename: true,
      inProcess: true
    });
    assert.equal(r1.ok, true);
    assert.equal(r1.method, 'hot_rename');

    // 第二次通过真实独立 Worker 子进程（inProcess: false）切换至 1M，并清理上一次遗留的已登记 .old
    const r2 = await unlock.applyUnlock({
      runtimeMode: 'cli',
      binaryPath: targetPath,
      mode: '1m',
      _testStateDir: stateDir
    });
    assert.equal(r2.ok, true);
    assert.equal(r2.appliedSpec.mode, '1m');
    assert.equal(fs.existsSync(untrackedOld), true, '未登记的 .old 文件绝不能被自动删除');

    // 验证 Electron 与 Live 模式的路径隔离：忽略外部传入的 binaryPath
    const resDir = path.join(tmpDir, 'electron_res');
    fs.mkdirSync(path.join(resDir, 'bin'), { recursive: true });
    const electronBin = path.join(resDir, 'bin', 'language_server.exe');
    fs.writeFileSync(electronBin, original);

    const elStatus = await unlock.getUnlockStatus({
      runtimeMode: 'electron',
      binaryPath: targetPath, // 试图传入另一个路径，应被忽略
      _testResourcesPath: resDir,
      _testStateDir: stateDir
    });
    assert.equal(elStatus.ok, true);
    assert.equal(elStatus.targetPath, electronBin, 'Electron 模式必须忽略外部 binaryPath 并强制绑定 process.resourcesPath');
    assert.equal(elStatus.diskState.mode, '256k');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
