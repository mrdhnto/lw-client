import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { pipeline } from 'node:stream/promises'

async function calculateHash(filePath) {
  const hash = createHash('sha256')
  await pipeline(
    fs.createReadStream(filePath),
    hash
  )
  return hash.digest('hex')
}

async function scanDirectory(dir, levelOneOnly = false) {
  const files = []
  const entries = await fs.promises.readdir(dir, { withFileTypes: true })
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      if (!levelOneOnly) {
        files.push(...await scanDirectory(fullPath, false))
      }
    } else {
      files.push(fullPath)
    }
  }
  return files
}

export async function scanPath(targetDir, onProgress, levelOneOnly = false) {
  if (!fs.existsSync(targetDir)) {
    throw new Error(`Directory not found: ${targetDir}`)
  }

  const stat = await fs.promises.stat(targetDir)
  if (!stat.isDirectory()) {
    throw new Error(`Not a directory: ${targetDir}`)
  }

  const allFiles = await scanDirectory(targetDir, levelOneOnly)
  const results = []
  
  for (let i = 0; i < allFiles.length; i++) {
    const filePath = allFiles[i]
    try {
      const stats = await fs.promises.stat(filePath)
      if (!stats.isFile()) continue

      const filename = path.basename(filePath)
      const fileHash = await calculateHash(filePath)

      results.push({
        filename,
        filepath: filePath,
        size: stats.size,
        hash: fileHash
      })

      onProgress(i + 1, allFiles.length, filename)
    } catch (err) {
      console.error(`Error processing ${filePath}:`, err.message)
    }
  }

  return results
}
