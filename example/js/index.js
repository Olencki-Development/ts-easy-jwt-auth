const { EasyJWTAuth } = require('../../dist')

const fakeUsersDb = []

const auth = new EasyJWTAuth({
  roles: {
    available: [
      'user',
      'admin'
    ],
    default: 'user'
  },
  secrets: {
    accessToken: 'my-access-secret',
    refreshToken: 'my-refresh-secret'
  }
})

auth.onRequestUserForUsername(async (username) => {
  const user = fakeUsersDb.find((user) => {
    return user.username === username
  })
  if (!user) {
    throw new Error('User is not found')
  }
  return user
})

async function main() {
  const user = {
    id: 1,
    username: 'my-user',
    password: 'password-user',
    role: '',
    hash: ''
  }
  const userResponse = await auth.register(user.username, user.password)
  console.log('Generated user auth system')
  user.hash = userResponse.userInfo.hash
  user.role = userResponse.userInfo.role

  const userTokens = userResponse.tokens

  fakeUsersDb.push(user)

  const admin = {
    id: 1,
    username: 'my-admin',
    password: 'password-admin',
    role: '',
    hash: ''
  }
  const adminResponse = await auth.register(admin.username, admin.password, 'admin')
  console.log('Generated admin auth system')
  admin.hash = adminResponse.userInfo.hash
  admin.role = adminResponse.userInfo.role

  const adminTokens = adminResponse.tokens

  fakeUsersDb.push(admin)

  await auth.validate(userTokens.access)
  console.log('Validated user with the auth system')
  await auth.validate(adminTokens.access)
  console.log('Validated admin with the auth system')

  try {
    await auth.validate(userTokens.access, ['admin'])
  } catch (e) {
    console.log('User is not allowed to access the admin only area')
  }

  await auth.validate(adminTokens.access, ['admin'])
  console.log('Validated admin with the auth system on an admin only area')

  await auth.refresh(userTokens.refresh)
  console.log('Refreshed auth token')
}

main()
