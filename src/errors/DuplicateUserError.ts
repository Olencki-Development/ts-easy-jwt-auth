import { IEasyJWTAuthError } from '../interfaces/IEasyJWTAuthError'

export default class DuplicateUserError
  extends Error
  implements IEasyJWTAuthError {
  statusCode: number

  constructor() {
    super('User already exists.')

    this.name = this.constructor.name
    this.statusCode = 400
  }
}
