import crypto from 'crypto'
import fs from 'fs'
import argon2 from 'argon2'
import {
    KDF_TIME_COST,
    KDF_MEMORY_COST,
    KDF_PARALLELISM,
    KEY_LENGTH,
    CIPHER_ALGORITHM,
    KDF_SALT_SIZE,
    IV_SIZE,
    TEXT_ENCODING,
    BASE_ENCODING,
    VAULT_VERSION,
    TEMP_SUFFIX
} from '../config.js'

export async function deriveKeyRaw(masterPassword, kdfSalt) {
    const raw = await argon2.hash(masterPassword, {
        type: argon2.argon2id,
        salt: kdfSalt,
        hashLength: KEY_LENGTH,
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
    const kdfSalt = crypto.randomBytes(KDF_SALT_SIZE) // stored outside encrypted payload
    const iv = crypto.randomBytes(IV_SIZE)
    const key = await deriveKeyRaw(masterPassword, kdfSalt)

    const plaintext = JSON.stringify(vaultData)

    const cipher = crypto.createCipheriv(CIPHER_ALGORITHM, key, iv)
    const cipherText = Buffer.concat([cipher.update(Buffer.from(plaintext, TEXT_ENCODING)), cipher.final()])
    const authTag = cipher.getAuthTag()

    console.log({ kdfSalt })
    return {
        kdfSalt: kdfSalt.toString(BASE_ENCODING),
        iv: iv.toString(BASE_ENCODING),
        authTag: authTag.toString(BASE_ENCODING),
        cipherText: cipherText.toString(BASE_ENCODING)
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
    const kdfSalt = Buffer.from(encryptedVault.kdfSalt, BASE_ENCODING)
    const iv = Buffer.from(encryptedVault.iv, BASE_ENCODING)
    const authTag = Buffer.from(encryptedVault.authTag, BASE_ENCODING)
    const cipherText = Buffer.from(encryptedVault.cipherText, BASE_ENCODING)

    const key = await deriveKeyRaw(masterPassword, kdfSalt)
    const decipher = crypto.createDecipheriv(CIPHER_ALGORITHM, key, iv)
    decipher.setAuthTag(authTag)

    let decrypted;
    try {
        decrypted = Buffer.concat([decipher.update(cipherText), decipher.final()])
    } catch (error) {
        throw new Error("Decryption failed - wrong password or corrupted file")
    }

    const vaultJson = JSON.parse(decrypted.toString(TEXT_ENCODING))

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
    const tmp = `${filePath}${TEMP_SUFFIX}`
    fs.writeFileSync(tmp, JSON.stringify(encryptedVault, null, 2), TEXT_ENCODING)
    fs.renameSync(tmp, filePath)
}

/**
 * Load .aunec JSON from disk
 * @param {*} filePath 
 * @returns 
 */
export function loadVaultFromFile(filePath) {
    if(!fs.existsSync(filePath)) throw new Error("Vault file not found")
    const raw = fs.readFileSync(filePath, TEXT_ENCODING)
    return JSON.parse(raw)
}

