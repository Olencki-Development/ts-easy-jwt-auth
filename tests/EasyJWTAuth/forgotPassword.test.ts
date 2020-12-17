import { EasyJWTAuth } from '../../src/EasyJWTAuth'

describe('src/EasyJWTAuth::forgotPassword', function () {
  let instance: EasyJWTAuth

  before(async function () {
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
  })

  it('should throw an error if user is not found', async function () {
    return instance
      .forgotPassword('username')
      .then(() => {
        this.assert.isNull(
          'Failed to throw an error. Should not have made it here.'
        )
      })
      .catch((error) => {
        this.assert.isNotNull(error)
      })
  })

  it('should return user item if username is found in system', async function () {
    this.assert.lengthOf(Object.keys(instance['_passwordResetTokens']), 0)
    const registerResult = await instance.register('username', 'password')
    instance.onRequestUserForUsername(async () => {
      return {
        hash: registerResult.userInfo.hash,
        role: registerResult.userInfo.role
      }
    })
    return instance
      .forgotPassword('username')
      .then((result) => {
        this.assert.hasAllKeys(result, ['user', 'tokens'])
        this.assert.isOk(result.user)
        this.assert.hasAllKeys(result.tokens, ['passwordReset'])
        this.assert.isString(result.tokens.passwordReset)
        this.assert.lengthOf(Object.keys(instance['_passwordResetTokens']), 1)
      })
      .catch((error) => {
        this.assert.isNull(error)
      })
  })
})
