import inquirer from "inquirer";
import { encryptVault, decryptVault, saveVaultToFile, loadVaultFromFile } from "./crypto/vaultCrypto.js";
import argon2 from 'argon2'
import fs from 'fs'
import path from "path";

const DEFAULT_FILENAME = 'vault.auenc'
const VAULTS_DIR = path.join(process.cwd(), 'vaults')

if (!fs.existsSync(VAULTS_DIR)) {
    fs.mkdirSync(VAULTS_DIR, {recursive: true})
}

// we are going to take it a step further and hide the files on default
async function createNewVaultFile(vaultName) {
    const fileName = `${vaultName}.auenc`
    const vaultPath = path.join(VAULTS_DIR, fileName)
    const { masterPassword } = await inquirer.prompt({
        type: "password",
        name: "masterPassword",
        message: "Set a master password for your vault",
        mask: "*",
        validate: (v) => (v.length >= 8 ? true : "Use at least 8 characters")
    })

    const passwordHash = await argon2.hash(masterPassword, {
        type: argon2.argon2id,
        timeCost: 3,
        memoryCost: 2**16
    })

    const vaultData = {
        version: 1,
        passwordHash,
        entries: []
    }

    const encrypted = await encryptVault(vaultData, masterPassword)
    saveVaultToFile(encrypted, vaultPath)
    console.log('New Vault Created:', DEFAULT_FILENAME, {vaultData, vaultPath})
}

async function uploadVaultFlow() {
    const {dirPath} = await inquirer.prompt({
        type: 'input', 
        name: 'dirPath',
        message: 'Enter the directory path containing vaults\n' +
               '(Hint: press Enter to use the default vaults folder):',
        default: VAULTS_DIR,
        //validate: (p) => (fs.existsSync(p) ? true : "File not found")
    })

    if (!fs.existsSync(dirPath) || !fs.statSync(dirPath).isDirectory()) {
        console.error('Invalid directory path')
        return
    }

    const vaultFiles = fs.readdirSync(dirPath).filter(file => file.endsWith('.auenc'))

    if (vaultFiles.length === 0) {
        console.error('No vault files found')
        return
    }

    const {choosenVault} = await inquirer.prompt([
        {
            type: 'list',
            name: 'choosenVault',
            message: 'Select a vault to open',
            choices: vaultFiles
        }
    ])

    const selectedPath = path.join(dirPath, choosenVault)
    
    if (!selectedPath) {
        console.log('You need to pick a path')
        return
    }
    
    const {masterPassword} = await inquirer.prompt({
        type: "password",
        name: "masterPassword",
        message: "Enter your master password:",
        mask: "*"
    })

    try {
        const encrypted = loadVaultFromFile(selectedPath)
        const vault = await decryptVault(encrypted, masterPassword)
        console.log("Vault opened, Entries count:", vault.entries.length)

        const {action} = await inquirer.prompt({
            type: "list",
            name: "action",
            message: "What would you like to do?",
            choices: ["List entries", "Add password entry", "Exit"]
        })

        if (action === "List entries") {
            vault.entries.forEach((e, i) => {
                console.log(`${i + 1}. ${e.url} - ${e.username} [${e.password}]`)
            })
        } else if (action === "Add password entry") {
            const {url, username, password} = await inquirer.prompt([
                {
                    type: "input",
                    name: "url",
                    message: "URL:"
                },
                {
                    type: "input",
                    name: "username",
                    message: "Username:"
                },
                {
                    type: "password",
                    name: "password",
                    message: "Password:",
                    mask: "*"
                }
            ])
            vault.entries.push({ type: "password", url, username, password })
            const updatedEncrypted = await encryptVault(vault, masterPassword)
            saveVaultToFile(updatedEncrypted, selectedPath)
            console.log("Entry added and vault saved.")
        }
        
    } catch (error) {
        console.error('Err', error.message)
    }
}

async function main() {
    const {choice} = await inquirer.prompt({
        type: "list",
        name: "choice",
        message: "Create new vault or open existing",
        choices: ["Create New", "Open Existing"]
    })
    if (choice === "Create New") {
        const {vaultName} = await inquirer.prompt([
            {
                type: 'input',
                name: 'vaultName',
                message: 'Enter vault file name (without extension):',
                validate: (input) => {
                    const trimmed = input.trim()
                    if (!trimmed) return 'File name cannot be empty'

                    if (/[<>:"/\\|?*]/.test(trimmed)) return 'Invalid characters in file name'

                    return true
                }
            }
        ])

        await createNewVaultFile(vaultName)
    }
        
    else 
        await uploadVaultFlow()
}

main()