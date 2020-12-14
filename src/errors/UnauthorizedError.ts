export default class UnauthorizedError extends Error {
  constructor() {
    super('Not authorized.')

    this.name = this.constructor.name
  }
}
