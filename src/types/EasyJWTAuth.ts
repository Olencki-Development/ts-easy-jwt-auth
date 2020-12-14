export type EasyJWTAuthOptions = {
  roles: {
    available: Roles
    default: Role
  }
  saltRounds?: number
  secrets: {
    accessToken: string
    refreshToken: string
  }
  accessTokenExpiresInMinutes?: number
}

export type Username = string
export type Password = string
export type Role = string
export type Roles = Role[]
export type PasswordHash = string
export type JsonWebToken = string
export type JsonWebTokenPayload = {
  username: Username
  role: Role
}

export type UserType = {
  [key: string]: any
  hash: PasswordHash
  role: Role
}
export type GetUserForUsernameCallback = (
  username: Username
) => Promise<UserType>

export type RegisterReturnValue = {
  userInfo: {
    hash: PasswordHash
    role: Role
  }
  tokens: {
    refresh: JsonWebToken
    access: JsonWebToken
  }
}

export type LoginReturnValue = {
  tokens: {
    refresh: JsonWebToken
    access: JsonWebToken
  }
}

export type AuthReturnValue = UserType