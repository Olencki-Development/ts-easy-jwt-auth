import { EasyJWTAuth } from '../../src/EasyJWTAuth'

describe('src/EasyJWTAuth::constructor', function () {
  it('should return instance of type ReduxProcess', function () {
    const instance = new EasyJWTAuth({
      roles: {
        available: ['user', 'admin'],
        default: 'user'
      },
      secrets: {
        accessToken: 'my-access-secret',
        refreshToken: 'my-refresh-secret'
      }
    })

    this.assert.instanceOf(instance, EasyJWTAuth)
    this.assert.deepEqual(instance.options, {
      roles: {
        available: ['user', 'admin'],
        default: 'user'
      },
      secrets: {
        accessToken: 'my-access-secret',
        refreshToken: 'my-refresh-secret'
      }
    })
    this.assert.deepEqual(instance['_tokens'], {})
    this.assert.throws(() => {
      return instance['_getUserForUsername']('username')
    })
  })
})
