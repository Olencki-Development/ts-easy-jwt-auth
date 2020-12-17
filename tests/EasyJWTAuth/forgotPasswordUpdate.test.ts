import { EasyJWTAuth } from '../../src/EasyJWTAuth'

describe('src/EasyJWTAuth::forgotPasswordUpdate', function () {
  let instance: EasyJWTAuth, token: string

  beforeEach(async function () {
    instance = new EasyJWTAuth({
      roles: {
        available: ['user', 'admin'],
        default: 'user'
      },
      secrets: {
        accessToken: 'my-access-secret',
        refreshToken: 'my-refresh-secret',
        passwordResetToken: 'my-reset-token'
      }
    })
    instance.onRequestUserForUsername(async () => {
      return {
        role: 'user',
        hash: 'hash'
      }
    })
    const result = await instance.forgotPassword('username')
    token = result.tokens.passwordReset
  })

  it('should throw an error if user is not found', async function () {
    instance.onRequestUserForUsername(() => {
      throw new Error('whoops')
    })
    return instance
      .forgotPasswordUpdate('invalid', 'new-pass', token)
      .then(() => {
        this.assert.isNull(
          'Failed to throw an error. Should not have made it here.'
        )
      })
      .catch((error) => {
        this.assert.isNotNull(error)
      })
  })

  it('should throw an error if token is not for user', async function () {
    return instance
      .forgotPasswordUpdate('username', 'new-pass', 'token')
      .then(() => {
        this.assert.isNull(
          'Failed to throw an error. Should not have made it here.'
        )
      })
      .catch((error) => {
        this.assert.isNotNull(error)
      })
  })

  it('should throw an error if token is not valid', async function () {
    instance['_passwordResetTokens']['username'] = 'token'
    return instance
      .forgotPasswordUpdate('username', 'new-pass', 'token')
      .then(() => {
        this.assert.isNull(
          'Failed to throw an error. Should not have made it here.'
        )
      })
      .catch((error) => {
        this.assert.isNotNull(error)
      })
  })

  it('should resolve if token belongs to user and the token is valid', async function () {
    this.assert.lengthOf(Object.keys(instance['_passwordResetTokens']), 1)
    return instance
      .forgotPasswordUpdate('username', 'new-pass', token)
      .then((result) => {
        this.assert.hasAllKeys(result, ['user'])
        this.assert.isOk(result.user)
        this.assert.lengthOf(Object.keys(instance['_passwordResetTokens']), 0)
      })
      .catch((error) => {
        this.assert.isNull(error)
      })
  })
})
