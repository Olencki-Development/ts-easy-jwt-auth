import { EasyJWTAuth } from '../../src/EasyJWTAuth'
import UnauthorizedError from '../../src/errors/UnauthorizedError'

describe('src/EasyJWTAuth::login', function () {
  let instance: EasyJWTAuth

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
    const registerResult = await instance.register('username', 'password')
    instance.onRequestUserForUsername(async () => {
      return {
        hash: registerResult.userInfo.hash,
        role: registerResult.userInfo.role
      }
    })
  })

  it('should throw error if password does not match', async function () {
    return instance
      .login('username', 'invalid-password')
      .then(() => {
        this.assert.isNull(
          'Failed to throw an error. Should not have made it here.'
        )
      })
      .catch((error) => {
        this.assert.instanceOf(error, UnauthorizedError)
      })
  })

  it('should resolve when successful', async function () {
    return instance
      .login('username', 'password')
      .then((result) => {
        this.assert.hasAllKeys(result, ['tokens', 'user'])
        this.assert.hasAllKeys(result.tokens, ['refresh', 'access'])
        this.assert.isString(result.tokens.access)
        this.assert.isString(result.tokens.refresh)
      })
      .catch((error) => {
        this.assert.isNull(error)
      })
  })
})
