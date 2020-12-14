import { EasyJWTAuth } from '../../src/EasyJWTAuth'
import ForbiddenError from '../../src/errors/ForbiddenError'

describe('src/EasyJWTAuth::refresh', function () {
  let instance: EasyJWTAuth
  let tokens: {
    refresh: string
    access: string
  }

  before(async function () {
    instance = new EasyJWTAuth({
      roles: {
        available: ['user', 'admin'],
        default: 'user'
      },
      secrets: {
        accessToken: 'my-access-secret',
        refreshToken: 'my-refresh-secret'
      }
    })
    const registerResult = await instance.register('username', 'password')
    tokens = registerResult.tokens
    instance.onRequestUserForUsername(async () => {
      return {
        hash: registerResult.userInfo.hash,
        role: registerResult.userInfo.role
      }
    })
  })

  it('should throw error if refreshToken is not found', async function () {
    return instance
      .refresh('invalid-token')
      .then(() => {
        this.assert.isNull(
          'Failed to throw an error. Should not have made it here.'
        )
      })
      .catch((error) => {
        this.assert.instanceOf(error, ForbiddenError)
      })
  })

  it('should resolve when refresh token is found', async function () {
    return instance
      .refresh(tokens.refresh)
      .then((result) => {
        this.assert.hasAllKeys(result, ['tokens'])
        this.assert.hasAllKeys(result.tokens, ['refresh', 'access'])
        this.assert.isString(result.tokens.access)
        this.assert.isString(result.tokens.refresh)
      })
      .catch((error) => {
        this.assert.isNull(error)
      })
  })
})
