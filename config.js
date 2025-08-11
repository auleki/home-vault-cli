import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';

// Check if .env file exists
const envPath = path.join(process.cwd(), '.env');
if (!fs.existsSync(envPath)) {
    console.error('❌ Error: .env file not found!');
    console.error('Please create a .env file with the required configuration variables.');
    console.error('You can copy from the example .env file or create one with the following variables:');
    console.error('');
    console.error('# Security Configuration');
    console.error('AUENC_KDF_TIME_COST=3');
    console.error('AUENC_KDF_MEMORY_COST=65536');
    console.error('AUENC_KDF_PARALLELISM=1');
    console.error('AUENC_KEY_LENGTH=32');
    console.error('AUENC_CIPHER_ALGORITHM=aes-256-gcm');
    console.error('AUENC_KDF_SALT_SIZE=16');
    console.error('AUENC_IV_SIZE=12');
    console.error('');
    console.error('# File System');
    console.error('AUENC_VAULTS_DIR=./vaults');
    console.error('AUENC_DEFAULT_FILENAME=vault.auenc');
    console.error('AUENC_TEXT_ENCODING=utf8');
    console.error('AUENC_BASE_ENCODING=base64');
    console.error('');
    console.error('# Password Policy');
    console.error('AUENC_MIN_PASSWORD_LENGTH=8');
    console.error('');
    console.error('# Application');
    console.error('AUENC_VAULT_VERSION=1');
    console.error('AUENC_TEMP_SUFFIX=.tmp');
    console.error('');
    process.exit(1);
}

// Load environment variables from .env file
const result = dotenv.config();
if (result.error) {
    console.error('❌ Error loading .env file:', result.error.message);
    process.exit(1);
}

// Security Configuration
export const KDF_TIME_COST = parseInt(process.env.AUENC_KDF_TIME_COST) ?? null
export const KDF_MEMORY_COST = parseInt(process.env.AUENC_KDF_MEMORY_COST) ?? null
export const KDF_PARALLELISM = parseInt(process.env.AUENC_KDF_PARALLELISM) ?? null
export const KEY_LENGTH = parseInt(process.env.AUENC_KEY_LENGTH) ?? null
export const CIPHER_ALGORITHM = process.env.AUENC_CIPHER_ALGORITHM  ?? null
export const KDF_SALT_SIZE = parseInt(process.env.AUENC_KDF_SALT_SIZE)  ?? null
export const IV_SIZE = parseInt(process.env.AUENC_IV_SIZE) ?? null

// File System Configuration
export const VAULTS_DIR = process.env.AUENC_VAULTS_DIR  ?? null
export const DEFAULT_FILENAME = process.env.AUENC_DEFAULT_FILENAME  ?? null
export const TEXT_ENCODING = process.env.AUENC_TEXT_ENCODING  ?? null
export const BASE_ENCODING = process.env.AUENC_BASE_ENCODING  ?? null

// Password Policy
export const MIN_PASSWORD_LENGTH = parseInt(process.env.AUENC_MIN_PASSWORD_LENGTH)  ?? null

// Application Configuration
export const VAULT_VERSION = parseInt(process.env.AUENC_VAULT_VERSION)  ?? null
export const TEMP_SUFFIX = process.env.AUENC_TEMP_SUFFIX  ?? null

// Helper function to get vault file extension
export const getVaultExtension = () => '.auenc';

// Helper function to get full vault path
export const getVaultPath = (vaultName) => {
    const fileName = `${vaultName}${getVaultExtension()}`;
    return path.join(VAULTS_DIR, fileName);
};
