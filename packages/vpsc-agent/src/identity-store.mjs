import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { constants, closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync,
  openSync, readFileSync, writeFileSync } from 'node:fs';
import { generateKeyPairSync } from 'node:crypto';
import { createPairingIdentityFromPkcs8 } from './pairing.mjs';

// This is an offline identity-store candidate, NOT connected to an agent route.
// Persistence never implies enrollment, trust, or server-side authorization.
const KEY_FILE = 'identity-v1.json';
const MAX_FILE_BYTES = 8192;
const FILE_MASK = 0o077;
const DIR_MASK = 0o077;
const FOLDER = '.vpsc-device';
const DOMAIN = 'VPSC-AGENT-KEY-v1';

function storageFolder(platform) {
  if (platform === 'win32') {
    const base = process.env.LOCALAPPDATA;
    if (typeof base !== 'string' || !path.isAbsolute(base)) {
      throw new Error('Windows LOCALAPPDATA must be absolute');
    }
    return path.join(base,'VPSCommander','device');
  }
  if (platform === 'linux' || platform === 'darwin') return path.join(os.homedir(),FOLDER);
  throw new Error('Unsupported device platform');
}

function assertStoreDir(dir,platform) {
  if (typeof dir !== 'string' || !path.isAbsolute(dir)) throw new TypeError('Invalid identity directory');
  mkdirSync(dir,{recursive:true,mode:0o700});
  const st=lstatSync(dir);
  if (!st.isDirectory() || st.isSymbolicLink()) throw new Error('Unsafe identity directory');
  if (platform !== 'win32' && (st.mode & DIR_MASK)) {
    throw new Error('Identity directory permissions must be owner-only');
  }
}

function powershellDpapi(op,input) {
  // Script body is static and contains no secrets. PKCS8 key material is sent
  // only through stdin, never in argv, the shell command or the output logs.
  const code = [
    "$ErrorActionPreference='Stop'",
    "$s=[Console]::In.ReadToEnd().Trim()",
    "$bytes=[Convert]::FromBase64String($s)",
    "$entropy=[Text.Encoding]::UTF8.GetBytes('"+DOMAIN+"')",
    "$scope=[Security.Cryptography.DataProtectionScope]::CurrentUser",
    "$cipher=[Security.Cryptography.ProtectedData]::"+(op==='protect'?'Protect':'Unprotect')+"($bytes,$entropy,$scope)",
    "[Console]::Out.Write([Convert]::ToBase64String($cipher))",
  ].join(';');
  const proc=spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-EncodedCommand',
    Buffer.from(code,'utf16le').toString('base64')],{
    input:Buffer.from(input).toString('base64'),encoding:'utf8',
    windowsHide:true,timeout:12_000,maxBuffer:8192,shell:false,
  });
  if (proc.error || proc.status !== 0 ||
      typeof proc.stdout !== 'string' || !/^[A-Za-z0-9+/=\s]+$/.test(proc.stdout.trim())) {
    throw new Error('Windows user-scoped key protection unavailable');
  }
  const output=Buffer.from(proc.stdout.trim(),'base64');
  if (output.length < 16 || output.length > 2048) throw new Error('Invalid DPAPI output');
  return output;
}

function parsePersisted(text,platform) {
  let envelope;
  try { envelope=JSON.parse(text); } catch { throw new Error('Invalid device identity envelope'); }
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope) ||
      Object.keys(envelope).sort().join(',') !== 'encoding,fingerprint,key,version' ||
      envelope.version !== 1 || typeof envelope.key !== 'string' ||
      envelope.key.length > 3000 || !/^[A-Za-z0-9+/]+={0,2}$/.test(envelope.key) ||
      !/^[a-f0-9]{64}$/.test(envelope.fingerprint)) {
    throw new Error('Invalid device identity envelope');
  }
  const required=platform==='win32'?'dpapi-current-user':'pkcs8-owner-file';
  if (envelope.encoding !== required) throw new Error('Wrong identity platform protection');
  let key=Buffer.from(envelope.key,'base64');
  if (key.length < 16 || key.length > 2048) throw new Error('Invalid key encoding');
  if (platform==='win32') key=powershellDpapi('unprotect',key);
  const identity=createPairingIdentityFromPkcs8(key);
  key.fill(0);
  if (identity.fingerprint !== envelope.fingerprint) throw new Error('Identity fingerprint mismatch');
  return identity;
}

export function loadOrCreateDeviceIdentity({
  directory=storageFolder(process.platform),platform=process.platform,
} = {}) {
  if (!['linux','darwin','win32'].includes(platform) || platform!==process.platform) {
    throw new Error('Identity store cannot impersonate a platform');
  }
  assertStoreDir(directory,platform);
  const filename=path.join(directory,KEY_FILE);
  const nofollow=constants.O_NOFOLLOW??0;
  let fd;
  try {
    fd=openSync(filename,constants.O_RDONLY|nofollow);
  } catch (error) {
    if (error?.code!=='ENOENT') throw error;
    // Generate a locally owned identity. A second contender wins atomically
    // with O_EXCL; the loser must load that existing winner.
    const {privateKey}=generateKeyPairSync('ed25519');
    const privateDer=privateKey.export({type:'pkcs8',format:'der'});
    const identity=createPairingIdentityFromPkcs8(privateDer);
    const stored=platform==='win32'?powershellDpapi('protect',privateDer):Buffer.from(privateDer);
    privateDer.fill(0);
    const envelope=JSON.stringify({version:1,
      encoding:platform==='win32'?'dpapi-current-user':'pkcs8-owner-file',
      fingerprint:identity.fingerprint,key:stored.toString('base64')})+'\n';
    stored.fill(0);
    try {
      fd=openSync(filename,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|nofollow,0o600);
      writeFileSync(fd,envelope,'utf8');
      fsyncSync(fd);
      closeSync(fd);
      fd=undefined;
      // File is complete before this process considers it usable.
      return loadOrCreateDeviceIdentity({directory,platform});
    } catch (e) {
      if(fd!==undefined)closeSync(fd);
      if (e?.code==='EEXIST')return loadOrCreateDeviceIdentity({directory,platform});
      throw e;
    }
  }
  try {
    const st=fstatSync(fd);
    if (!st.isFile() || st.size <= 0 || st.size > MAX_FILE_BYTES ||
        (platform !== 'win32' && (st.mode & FILE_MASK))) {
      throw new Error('Unsafe identity file');
    }
    return parsePersisted(readFileSync(fd,'utf8'),platform);
  } finally {
    closeSync(fd);
  }
}
