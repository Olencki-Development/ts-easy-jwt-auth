import { EasyJWTAuth } from '../../src/EasyJWTAuth'
import ForbiddenError from '../../src/errors/ForbiddenError'

describe('src/EasyJWTAuth::validate', function () {
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

  it('should throw error if accessToken is not found', async function () {
    return instance
      .validate('invalid-token')
      .then(() => {
        this.assert.isNull(
          'Failed to throw an error. Should not have made it here.'
        )
      })
      .catch((error) => {
        this.assert.instanceOf(error, ForbiddenError)
      })
  })

  it('should throw error if role is not valid', async function () {
    return instance
      .validate(tokens.access, ['admin'])
      .then(() => {
        this.assert.isNull(
          'Failed to throw an error. Should not have made it here.'
        )
      })
      .catch((error) => {
        this.assert.instanceOf(error, ForbiddenError)
      })
  })

  it('should resolve when accessToken is found', async function () {
    return instance
      .validate(tokens.access)
      .then((result) => {
        this.assert.hasAllKeys(result, ['user', 'tokens'])
        this.assert.hasAllKeys(result.tokens, ['access', 'refresh'])
        this.assert.isString(result.tokens.access)
        this.assert.isString(result.tokens.refresh)
        this.assert.hasAllKeys(result.user, ['hash', 'role'])
        this.assert.isString(result.user.hash)
        this.assert.isString(result.user.role)
      })
      .catch((error) => {
        this.assert.isNull(error)
      })
  })

  it('should resolve when accessToken is passed as entier header and is found', async function () {
    return instance
      .validate(`Bearer ${tokens.access}`)
      .then((result) => {
        this.assert.hasAllKeys(result, ['user', 'tokens'])
        this.assert.hasAllKeys(result.tokens, ['access', 'refresh'])
        this.assert.isString(result.tokens.access)
        this.assert.isString(result.tokens.refresh)
        this.assert.hasAllKeys(result.user, ['hash', 'role'])
        this.assert.isString(result.user.hash)
        this.assert.isString(result.user.role)
      })
      .catch((error) => {
        console.log(error)
        this.assert.isNull(error)
      })
  })

  it('should resolve when accessToken is found and role is satisfied', async function () {
    return instance
      .validate(tokens.access, ['user'])
      .then((result) => {
        this.assert.hasAllKeys(result, ['user', 'tokens'])
        this.assert.hasAllKeys(result.tokens, ['access', 'refresh'])
        this.assert.isString(result.tokens.access)
        this.assert.isString(result.tokens.refresh)
        this.assert.hasAllKeys(result.user, ['hash', 'role'])
        this.assert.isString(result.user.hash)
        this.assert.isString(result.user.role)
      })
      .catch((error) => {
        this.assert.isNull(error)
      })
  })
})
