import crypto from 'crypto'
import fs from 'fs'
import argon2 from 'argon2'

const KDF_TIME_COST = 3
const KDF_MEMORY_COST = 2 ** 16
const KDF_PARALLELISM = 1
const KEY_LEN = 32

const aesKey = "aes-256-gcm"
const encoding = "utf8"
const baseEncoding = "base64"

export async function deriveKeyRaw(masterPassword, kdfSalt) {
    const raw = await argon2.hash(masterPassword, {
        type: argon2.argon2id,
        salt: kdfSalt,
        hashLength: KEY_LEN,
        timeCost: KDF_TIME_COST,
        memoryCost: KDF_MEMORY_COST,
        parallelism: KDF_PARALLELISM,
        raw: true
    })
    return raw
}

/**
 * Encrypts a JS object into an .auenc structure
 * Returns JSON serializable object
 * @param {*} vaultData 
 * @param {*} masterPassword 
 * @returns 
 */
export async function encryptVault(vaultData, masterPassword) {
    const kdfSalt = crypto.randomBytes(16) // stored outside encrypted payload
    const iv = crypto.randomBytes(12)
    const key = await deriveKeyRaw(masterPassword, kdfSalt)

    const plaintext = JSON.stringify(vaultData)

    const cipher = crypto.createCipheriv(aesKey, key, iv)
    const cipherText = Buffer.concat([cipher.update(Buffer.from(plaintext, encoding)), cipher.final()])
    const authTag = cipher.getAuthTag()

    console.log({ kdfSalt })
    return {
        kdfSalt: kdfSalt.toString(baseEncoding),
        iv: iv.toString(baseEncoding),
        authTag: authTag.toString(baseEncoding),
        cipherText: cipherText.toString(baseEncoding)
    }
}

/**
 * Decrypts .auenc structure using masterPassword
 * Returns the parsed vault JSON (object)
 * @param {*} encryptedVault 
 * @param {*} masterPassword 
 * @returns 
 */
export async function decryptVault(encryptedVault, masterPassword) {
    const kdfSalt = Buffer.from(encryptedVault.kdfSalt, baseEncoding)
    const iv = Buffer.from(encryptedVault.iv, baseEncoding)
    const authTag = Buffer.from(encryptedVault.authTag, baseEncoding)
    const cipherText = Buffer.from(encryptedVault.cipherText, baseEncoding)

    const key = await deriveKeyRaw(masterPassword, kdfSalt)
    const decipher = crypto.createDecipheriv(aesKey, key, iv)
    decipher.setAuthTag(authTag)

    let decrypted;
    try {
        decrypted = Buffer.concat([decipher.update(cipherText), decipher.final()])
    } catch (error) {
        throw new Error("Decryption failed - wrong password or corrupted file")
    }

    const vaultJson = JSON.parse(decrypted.toString(encoding))

    // verify master password by checking stored encoded argon hash
    if (!vaultJson.passwordHash) {
        throw new Error("Malformed vault: missing password hash")
    }

    const ok = await argon2.verify(vaultJson.passwordHash, masterPassword)

    if (!ok) {
        throw new Error('Password verification failed - wrong master password')
    }

    return vaultJson
}

/**
 * Save .aunec JSON to file (atomic write)
 * @param {*} encryptedVault 
 * @param {*} filePath
 */
export function saveVaultToFile(encryptedVault, filePath) {
    const tmp = `${filePath}.tmp`
    fs.writeFileSync(tmp, JSON.stringify(encryptedVault, null, 2), encoding)
    fs.renameSync(tmp, filePath)
}

/**
 * Load .aunec JSON from disk
 * @param {*} filePath 
 * @returns 
 */
export function loadVaultFromFile(filePath) {
    if(!fs.existsSync(filePath)) throw new Error("Vault file not found")
    const raw = fs.readFileSync(filePath, encoding)
    return JSON.parse(raw)
}

