export declare type EasyJWTAuthOptions = {
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
export declare type Username = string
export declare type Password = string
export declare type Role = string
export declare type Roles = Role[]
export declare type PasswordHash = string
export declare type JsonWebToken = string
export declare type JsonWebTokenPayload = {
  username: Username
  role: Role
}
export declare type UserType = {
  [key: string]: any
  hash: PasswordHash
  role: Role
}
export declare type GetUserForUsernameCallback = (
  username: Username
) => Promise<UserType>
export declare type RegisterReturnValue = {
  userInfo: {
    hash: PasswordHash
    role: Role
  }
  tokens: {
    refresh: JsonWebToken
    access: JsonWebToken
  }
}
export declare type LoginReturnValue = {
  tokens: {
    refresh: JsonWebToken
    access: JsonWebToken
  }
}
export declare type AuthReturnValue = UserType
