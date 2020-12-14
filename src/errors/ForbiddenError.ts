export default class ForbiddenError extends Error {
  constructor() {
    super('Forbidden.')

    this.name = this.constructor.name
  }
}
