import { EasyJWTAuth } from '../../src/EasyJWTAuth'
import InvalidRoleError from '../../src/errors/InvalidRoleError'
import DuplicateUserError from '../../src/errors/DuplicateUserError'

describe('src/EasyJWTAuth::register', function () {
  let instance: EasyJWTAuth

  beforeEach(function () {
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

  it('should throw error if role is not valid', async function () {
    return instance
      .register('my-user', 'my-pass', 'invalid-role')
      .then(() => {
        this.assert.isNull(
          'Failed to throw an error. Should not have made it here.'
        )
      })
      .catch((error) => {
        this.assert.instanceOf(error, InvalidRoleError)
      })
  })

  it('should throw error if user already exists', async function () {
    instance.onRequestUserForUsername(async (username) => {
      return {
        username,
        role: 'user',
        hash: 'asdf'
      }
    })
    return instance
      .register('my-user', 'my-pass')
      .then(() => {
        this.assert.isNull(
          'Failed to throw an error. Should not have made it here.'
        )
      })
      .catch((error) => {
        this.assert.instanceOf(error, DuplicateUserError)
      })
  })

  it('should resolve without role being provided', async function () {
    return instance
      .register('my-user', 'my-pass')
      .then((result) => {
        this.assert.hasAllKeys(result, ['userInfo', 'tokens'])
        this.assert.hasAllKeys(result.userInfo, ['hash', 'role'])
        this.assert.hasAllKeys(result.tokens, ['refresh', 'access'])
        this.assert.equal(result.userInfo.role, 'user')
        this.assert.isString(result.userInfo.hash)
        this.assert.isString(result.tokens.access)
        this.assert.isString(result.tokens.refresh)
      })
      .catch((error) => {
        this.assert.isNull(error)
      })
  })

  it('should resolve with role being provided', async function () {
    return instance
      .register('my-user', 'my-pass', 'admin')
      .then((result) => {
        this.assert.hasAllKeys(result, ['userInfo', 'tokens'])
        this.assert.hasAllKeys(result.userInfo, ['hash', 'role'])
        this.assert.hasAllKeys(result.tokens, ['refresh', 'access'])
        this.assert.equal(result.userInfo.role, 'admin')
        this.assert.isString(result.userInfo.hash)
        this.assert.isString(result.tokens.access)
        this.assert.isString(result.tokens.refresh)
      })
      .catch((error) => {
        this.assert.isNull(error)
      })
  })
})
