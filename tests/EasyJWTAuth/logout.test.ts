import { EasyJWTAuth } from '../../src/EasyJWTAuth'
import ForbiddenError from '../../src/errors/ForbiddenError'

describe('src/EasyJWTAuth::logout', function () {
  let instance: EasyJWTAuth
  let tokens: {
    refresh: string
    access: string
  }

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
    tokens = registerResult.tokens
    instance.onRequestUserForUsername(async () => {
      return {
        hash: registerResult.userInfo.hash,
        role: registerResult.userInfo.role
      }
    })
  })

  it('should throw error if accessToken is not found', async function () {
    this.assert.throws(() => {
      instance.logout('invalid-token')
    }, ForbiddenError)
  })

  it('should resolve when accessToken is found', async function () {
    this.assert.lengthOf(Object.keys(instance['_tokens']), 1)
    instance.logout(tokens.access)
    this.assert.lengthOf(Object.keys(instance['_tokens']), 0)
  })
})
