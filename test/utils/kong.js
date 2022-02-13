const { exec } = require('child_process')

const reset = () => {
  return new Promise((resolve, reject) => {
    exec('deck reset --force', (err, stdout, stderr) => {
      if (err) {
        return reject(err)
      }
      return resolve({ stdout, stderr })
    }
    )
  })
}

module.exports = { reset }
