import { IEasyJWTAuthError } from '../interfaces/IEasyJWTAuthError'
export default class DuplicateUserError
  extends Error
  implements IEasyJWTAuthError {
  statusCode: number
  constructor()
}
