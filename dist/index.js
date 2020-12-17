"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.errors = exports.EasyJWTAuth = void 0;
const UnauthorizedError_1 = __importDefault(require("./errors/UnauthorizedError"));
const ForbiddenError_1 = __importDefault(require("./errors/ForbiddenError"));
const InvalidRoleError_1 = __importDefault(require("./errors/InvalidRoleError"));
var EasyJWTAuth_1 = require("./EasyJWTAuth");
Object.defineProperty(exports, "EasyJWTAuth", { enumerable: true, get: function () { return EasyJWTAuth_1.EasyJWTAuth; } });
exports.errors = {
    UnauthorizedError: UnauthorizedError_1.default,
    ForbiddenError: ForbiddenError_1.default,
    InvalidRoleError: InvalidRoleError_1.default
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvaW5kZXgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7O0FBQUEsbUZBQTBEO0FBQzFELDZFQUFvRDtBQUNwRCxpRkFBd0Q7QUFFeEQsNkNBQTJDO0FBQWxDLDBHQUFBLFdBQVcsT0FBQTtBQUNQLFFBQUEsTUFBTSxHQUFHO0lBQ3BCLGlCQUFpQixFQUFqQiwyQkFBaUI7SUFDakIsY0FBYyxFQUFkLHdCQUFjO0lBQ2QsZ0JBQWdCLEVBQWhCLDBCQUFnQjtDQUNqQixDQUFBIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IFVuYXV0aG9yaXplZEVycm9yIGZyb20gJy4vZXJyb3JzL1VuYXV0aG9yaXplZEVycm9yJ1xuaW1wb3J0IEZvcmJpZGRlbkVycm9yIGZyb20gJy4vZXJyb3JzL0ZvcmJpZGRlbkVycm9yJ1xuaW1wb3J0IEludmFsaWRSb2xlRXJyb3IgZnJvbSAnLi9lcnJvcnMvSW52YWxpZFJvbGVFcnJvcidcblxuZXhwb3J0IHsgRWFzeUpXVEF1dGggfSBmcm9tICcuL0Vhc3lKV1RBdXRoJ1xuZXhwb3J0IGNvbnN0IGVycm9ycyA9IHtcbiAgVW5hdXRob3JpemVkRXJyb3IsXG4gIEZvcmJpZGRlbkVycm9yLFxuICBJbnZhbGlkUm9sZUVycm9yXG59XG4iXX0=