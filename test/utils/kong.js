const { exec } = require('child_process')
const fs = require('fs').promises
const uuid = require('uuid')
const { sleep } = require('sleep')
const YAML = require('yaml')

const reset = async () => {
  await _reset()
  await sleep(1)
}

const _reset = () => {
  return new Promise((resolve, reject) => {
    exec('deck reset --force', (err, stdout, stderr) => {
      if (err) {
        return reject(err)
      }
      return resolve({ stdout, stderr })
    })
  })
}

const sync = async (config) => {
  const tempFileName = `./.${uuid.v4()}.yaml`
  let res
  try {
    await fs.writeFile(tempFileName, toYaml(config))
    res = await _sync(tempFileName)
  } finally {
    await fs.unlink(tempFileName)
  }
  await sleep(1)
  return res
}

const _sync = (kongFile) => {
  return new Promise((resolve, reject) => {
    exec(`deck sync --state ${kongFile}`, (err, stdout, stderr) => {
      if (err) {
        return reject(err)
      }
      return resolve({ stdout, stderr })
    })
  })
}

const toYaml = (object) => {
  const doc = new YAML.Document()
  doc.contents = object
  return doc.toString()
}

module.exports = { reset, sync }
