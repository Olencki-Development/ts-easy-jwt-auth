import { IEasyJWTAuthError } from '../interfaces/IEasyJWTAuthError'

export default class UnauthorizedError
  extends Error
  implements IEasyJWTAuthError {
  statusCode: number

  constructor() {
    super('Unauthorized.')

    this.name = this.constructor.name
    this.statusCode = 401
  }
}
