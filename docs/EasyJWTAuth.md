# Easy JWT Auth
The `EasyJWTAuth` class is responsible for handling user operations and tokens management. The access and refresh tokens are kept in memory. This class registers, authenticates, and validates a users access. It will also refresh the access token.

## Overview
ReduxProcessGroup is a class that should be instantiated. It takes an `options` argument that dictates the parameters for the class.

### Arguments
* `options` - The options object contains a few required keys.
  * `roles` - The roles object contains a few required keys that dictate the user roles.
    * `available` - An array of strings that indicate the available user roles.
    * `default` - A default role for a user if one is not specified.
  * `saltRounds` - An optional parameter that indicates the number of times the password should be salted. (Default 10)
  * `secrets` - The secrets object contains a few required keys that dictate the JWT secrets.
    * `accessToken` - The secret used for signing the access token.
    * `refreshToken` - The secret used for signing the refresh token.
    * `passwordResetToken` - The secret used for signing the password reset token.
  * `accessTokenExpiresInMinutes` - An optional parameter that indicates number of minutes that an access token will be valid for. (Default 90)
  * `passwordResetTokenExpiresInMinutes` - An optional parameter that indicates number of minutes that a password reset token will be valid for. (Default 10)

### Methods

Once `EasyJWTAuth` has been implemented there are a number of available methods.
```typescript
onRequestUserForUsername(cb: GetUserForUsernameCallback): void
```
  * This method takes a function as the parameter. The function has one argument, the username of the user that is being requested. This should return a user for the specific username or throw an error. The user object must have a `hash` (hashed password) and `role` (user role) property.

```typescript
register(username: Username, password: Password, role?: Role): Promise<RegisterReturnValue>
```
  * This method should be called when a user should be registered with the auth system. A password is hashed and a role is assigned. Then the refresh and access token are generated.

```typescript
login(username: Username, password: Password): Promise<LoginReturnValue>
```
  * This method should be called when a user should be authenticated with the database. The existing hashed password is compared against the provided password. Any refresh or access token tokens are generated.

```typescript
refresh(refreshToken: JsonWebToken): Promise<LoginReturnValue>
```
  * This method should be called when a user needs a new access token. The existing access token is removed from the system and a new one is registered.

```typescript
logout(accessToken: JsonWebToken): void
```
  * This method should be called a user's refresh and access tokens should be invalidated. They are removed from the list of available tokens.

```typescript
forgotPassword(username: Username): Promise<ForgotPasswordReturnValue>
```
  * This method should be called when a user has forgotten their password and wants to reset it. A code is generated and returned for the user. This code should be sent to the user for subsequent password reset validation.

```typescript
forgotPasswordUpdate(username: Username, newPassword: Password, passwordResetToken: JsonWebToken): Promise<ForgotPasswordUpdateReturnValue>
```
  * This method should be called when a user is attempting to reset their password. The previously generated reset token is provided, validated, and checked against the user. If it is correct and valid, the token is deleted and the new password is hashed and assigned to the user object. The user object is then returned.

```typescript
validate(accessToken: JsonWebToken, acceptedRoles: Roles = []): Promise<AuthReturnValue>
```
  * This method should be called when a user's access token should be validated with the auth system. If a role is passed as an argument, the user's role will be checked as well. If it does not match the accepted roles, it will not grant the user access.

## Example
```typescript
type User = {
  id: number
  username: string
  role: string
  hash: string
}

const fakeUsersDb: User[] = []

const auth = new EasyJWTAuth({
  roles: {
    available: ['user', 'admin'],
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
```
