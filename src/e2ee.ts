const encoder = new TextEncoder();
const decoder = new TextDecoder();
const KEY_STORAGE_PREFIX = "kmct-e2ee-private-v1:";

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  bytes.forEach((b) => { binary += String.fromCharCode(b); });
  return btoa(binary);
}
function fromBase64(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}

export async function ensureE2EEKeyPair(userId: string): Promise<{ publicKey: string; privateKey: CryptoKey }> {
  const storageKey = KEY_STORAGE_PREFIX + userId;
  const stored = localStorage.getItem(storageKey);
  if (stored) {
    try {
      const parsed = JSON.parse(stored);
      const privateKey = await crypto.subtle.importKey("jwk", parsed.privateKey, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey", "deriveBits"]);
      return { publicKey: parsed.publicKey, privateKey };
    } catch {
      // A malformed or incompatible local key is replaced below.
    }
  }
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
  const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  localStorage.setItem(storageKey, JSON.stringify({ publicKey: JSON.stringify(publicJwk), privateKey: privateJwk }));
  const privateKey = await crypto.subtle.importKey("jwk", privateJwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"]);
  return { publicKey: JSON.stringify(publicJwk), privateKey };
}

async function deriveAesKey(privateKey: CryptoKey, peerPublicKey: string): Promise<CryptoKey> {
  const jwk = JSON.parse(peerPublicKey);
  const publicKey = await crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256);
  const material = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: encoder.encode("KMCT-Community-E2EE-v1"), info: encoder.encode("private-chat") },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encryptChatPayload(userId: string, peerPublicKey: string, data: ArrayBuffer | Uint8Array): Promise<string> {
  const own = await ensureE2EEKeyPair(userId);
  const key = await deriveAesKey(own.privateKey, peerPublicKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes);
  return "E2EE1:" + JSON.stringify({ iv: toBase64(iv), data: toBase64(new Uint8Array(ciphertext)) });
}

export async function decryptChatPayload(userId: string, peerPublicKey: string, value: string): Promise<Uint8Array> {
  if (!value.startsWith("E2EE1:")) throw new Error("This message is not end-to-end encrypted.");
  const payload = JSON.parse(value.slice(6));
  const own = await ensureE2EEKeyPair(userId);
  const key = await deriveAesKey(own.privateKey, peerPublicKey);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64(payload.iv) }, key, fromBase64(payload.data));
  return new Uint8Array(plain);
}

import type { SupabaseClient } from "@supabase/supabase-js";

function bytesToB64(bytes: Uint8Array): string {
  let binary = "";
  bytes.forEach((b) => { binary += String.fromCharCode(b); });
  return btoa(binary);
}
function b64ToBytes(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}
async function backupKeyForPassword(privateJwk: JsonWebKey, password: string, salt: Uint8Array): Promise<string> {
  const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:310000,hash:"SHA-256"},material,{name:"AES-GCM",length:256},false,["encrypt"]);
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,encoder.encode(JSON.stringify(privateJwk)));
  return JSON.stringify({iv:bytesToB64(iv),data:bytesToB64(new Uint8Array(cipher))});
}
async function restoreKeyFromPassword(backup: string, password: string, salt: Uint8Array): Promise<JsonWebKey> {
  const payload=JSON.parse(backup);
  const material=await crypto.subtle.importKey("raw",encoder.encode(password),"PBKDF2",false,["deriveKey"]);
  const key=await crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:310000,hash:"SHA-256"},material,{name:"AES-GCM",length:256},false,["decrypt"]);
  const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv:b64ToBytes(payload.iv)},key,b64ToBytes(payload.data));
  return JSON.parse(decoder.decode(plain)) as JsonWebKey;
}

/**
 * Call immediately after password sign-in. The private key is backed up encrypted
 * with a password-derived key, so Supabase stores ciphertext only.
 * Requires profiles.e2ee_private_key_backup and profiles.e2ee_backup_salt columns.
 */
export async function initializeAccountE2EEKey(
  supabase: SupabaseClient,
  userId: string,
  password: string,
): Promise<void> {
  if (!password) throw new Error("Enter your password to securely prepare messaging on this device.");
  const storageKey=KEY_STORAGE_PREFIX+userId;
  const profile=await supabase.from("profiles").select("e2ee_private_key_backup,e2ee_backup_salt,e2ee_public_key").eq("id",userId).maybeSingle();
  if(profile.error) throw new Error("Secure key backup setup failed: "+profile.error.message);
  const backup=profile.data?.e2ee_private_key_backup as string|undefined;
  const saltText=profile.data?.e2ee_backup_salt as string|undefined;
  if(backup&&saltText){
    const salt=b64ToBytes(saltText);
    let privateJwk:JsonWebKey;
    try { privateJwk=await restoreKeyFromPassword(backup,password,salt); }
    catch { throw new Error("Could not unlock your messaging key. Check your password. Your existing messages have not been changed."); }
    const privateKey=await crypto.subtle.importKey("jwk",privateJwk,{name:"ECDH",namedCurve:"P-256"},false,["deriveKey","deriveBits"]);
    const publicKey=profile.data?.e2ee_public_key as string|undefined;
    if(!publicKey) throw new Error("Your account's public messaging key is missing. Keep the original device and contact support before resetting keys.");
    localStorage.setItem(storageKey,JSON.stringify({publicKey,privateKey:privateJwk}));
    return;
  }
  // First device: preserve its existing key if present, then create an encrypted backup.
  const existing=localStorage.getItem(storageKey);
  let privateJwk:JsonWebKey;
  let publicKey:string;
  if(existing){
    const parsed=JSON.parse(existing); privateJwk=parsed.privateKey; publicKey=parsed.publicKey;
  } else {
    const pair=await crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveKey","deriveBits"]);
    const publicJwk=await crypto.subtle.exportKey("jwk",pair.publicKey);
    privateJwk=await crypto.subtle.exportKey("jwk",pair.privateKey);
    publicKey=JSON.stringify(publicJwk);
    localStorage.setItem(storageKey,JSON.stringify({publicKey,privateKey:privateJwk}));
  }
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const encrypted=await backupKeyForPassword(privateJwk,password,salt);
  const save=await supabase.from("profiles").update({e2ee_public_key:publicKey,e2ee_private_key_backup:encrypted,e2ee_backup_salt:bytesToB64(salt)}).eq("id",userId);
  if(save.error) throw new Error("Could not save encrypted messaging-key backup: "+save.error.message);
}
