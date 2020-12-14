"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.EasyJWTAuth = void 0;
const bcrypt_1 = __importDefault(require("bcrypt"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const UnauthorizedError_1 = __importDefault(require("./errors/UnauthorizedError"));
const ForbiddenError_1 = __importDefault(require("./errors/ForbiddenError"));
const InvalidRoleError_1 = __importDefault(require("./errors/InvalidRoleError"));
const defaultGetUserForUsername = () => {
    throw new Error(`IEasyJWTAuth::onRequestUserForUsername has not been set.`);
};
class EasyJWTAuth {
    constructor(options) {
        this.getUserForUsername = defaultGetUserForUsername;
        this.tokens = {}; /* refreshToken -> accessToken */
        this.options = options;
    }
    async register(username, password, role) {
        const saltRounds = this.options.saltRounds || 10;
        const hash = await bcrypt_1.default.hash(password, saltRounds);
        const _role = role || this.options.roles.default;
        if (!this.options.roles.available.includes(_role)) {
            throw new InvalidRoleError_1.default();
        }
        const refreshToken = this._getRefreshToken(username, _role);
        const accessToken = this._getAccessToken(username, _role);
        this.tokens[refreshToken] = accessToken;
        return {
            userInfo: {
                hash,
                role: _role
            },
            tokens: {
                refresh: refreshToken,
                access: accessToken
            }
        };
    }
    async login(username, password) {
        const user = await this.getUserForUsername(username);
        const matches = await bcrypt_1.default.compare(password, user.hash);
        if (!matches) {
            throw new UnauthorizedError_1.default();
        }
        const refreshToken = this._getRefreshToken(username, user.role);
        const accessToken = this._getAccessToken(username, user.role);
        this.tokens[refreshToken] = accessToken;
        return {
            tokens: {
                refresh: refreshToken,
                access: accessToken
            }
        };
    }
    async refresh(refreshToken) {
        const existingAccessToken = this.tokens[refreshToken];
        if (!existingAccessToken) {
            throw new ForbiddenError_1.default();
        }
        const payload = jsonwebtoken_1.default.verify(refreshToken, this.options.secrets.refreshToken);
        const accessToken = this._getAccessToken(payload.username, payload.role);
        this.tokens[refreshToken] = accessToken;
        return {
            tokens: {
                refresh: refreshToken,
                access: accessToken
            }
        };
    }
    logout(accessToken) {
        const item = Object.entries(this.tokens).find(([_, access]) => {
            return access === accessToken;
        });
        if (!item) {
            throw new ForbiddenError_1.default();
        }
        const refreshToken = item[0];
        delete this.tokens[refreshToken];
    }
    async validate(accessToken, acceptedRoles = []) {
        const item = Object.entries(this.tokens).find(([_, access]) => {
            return access === accessToken;
        });
        if (!item) {
            throw new ForbiddenError_1.default();
        }
        const payload = jsonwebtoken_1.default.verify(accessToken, this.options.secrets.accessToken);
        let hasRole = false;
        if (acceptedRoles.length > 0) {
            acceptedRoles.forEach(role => {
                if (role === payload.role) {
                    hasRole = true;
                }
            });
        }
        else {
            hasRole = true;
        }
        if (!hasRole) {
            throw new ForbiddenError_1.default();
        }
        return this.getUserForUsername(payload.username);
    }
    onRequestUserForUsername(cb) {
        this.getUserForUsername = cb;
    }
    _getAccessToken(username, role) {
        const expiresIn = this.options.accessTokenExpiresInMinutes || 90;
        const accessToken = jsonwebtoken_1.default.sign({
            username,
            role
        }, this.options.secrets.accessToken, {
            expiresIn: `${expiresIn}m`
        });
        return accessToken;
    }
    _getRefreshToken(username, role) {
        const refreshToken = jsonwebtoken_1.default.sign({
            username,
            role
        }, this.options.secrets.refreshToken);
        return refreshToken;
    }
}
exports.EasyJWTAuth = EasyJWTAuth;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiRWFzeUpXVEF1dGguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvRWFzeUpXVEF1dGgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7O0FBQUEsb0RBQTJCO0FBQzNCLGdFQUE4QjtBQUM5QixtRkFBMEQ7QUFDMUQsNkVBQW9EO0FBQ3BELGlGQUF3RDtBQWdCeEQsTUFBTSx5QkFBeUIsR0FBK0IsR0FBRyxFQUFFO0lBQ2pFLE1BQU0sSUFBSSxLQUFLLENBQUMsMERBQTBELENBQUMsQ0FBQTtBQUM3RSxDQUFDLENBQUE7QUFFRCxNQUFhLFdBQVc7SUFNdEIsWUFBYSxPQUEyQjtRQUg5Qix1QkFBa0IsR0FBK0IseUJBQXlCLENBQUE7UUFDMUUsV0FBTSxHQUF1QyxFQUFFLENBQUEsQ0FBQyxpQ0FBaUM7UUFHekYsSUFBSSxDQUFDLE9BQU8sR0FBRyxPQUFPLENBQUE7SUFDeEIsQ0FBQztJQUVELEtBQUssQ0FBQyxRQUFRLENBQUMsUUFBa0IsRUFBRSxRQUFrQixFQUFFLElBQVc7UUFDaEUsTUFBTSxVQUFVLEdBQUcsSUFBSSxDQUFDLE9BQU8sQ0FBQyxVQUFVLElBQUksRUFBRSxDQUFBO1FBQ2hELE1BQU0sSUFBSSxHQUFHLE1BQU0sZ0JBQU0sQ0FBQyxJQUFJLENBQUMsUUFBUSxFQUFFLFVBQVUsQ0FBQyxDQUFBO1FBRXBELE1BQU0sS0FBSyxHQUFHLElBQUksSUFBSSxJQUFJLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxPQUFPLENBQUE7UUFDaEQsSUFBSSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsS0FBSyxDQUFDLFNBQVMsQ0FBQyxRQUFRLENBQUMsS0FBSyxDQUFDLEVBQUU7WUFDakQsTUFBTSxJQUFJLDBCQUFnQixFQUFFLENBQUE7U0FDN0I7UUFHRCxNQUFNLFlBQVksR0FBRyxJQUFJLENBQUMsZ0JBQWdCLENBQUMsUUFBUSxFQUFFLEtBQUssQ0FBQyxDQUFBO1FBQzNELE1BQU0sV0FBVyxHQUFHLElBQUksQ0FBQyxl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UUFFRCxPQUFPLFdBQVcsQ0FBQTtJQUNwQixDQUFDO0lBRVMsZ0JBQWdCLENBQUMsUUFBa0IsRUFBRSxJQUFVO1FBQ3ZELE1BQU0sWUFBWSxHQUFHLHNCQUFHLENBQUMsSUFBSSxDQUMzQjtZQUNFLFFBQVE7WUFDUixJQUFJO1NBQ0wsRUFDRCxJQUFJLENBQUMsT0FBTyxDQUFDLE9BQU8sQ0FBQyxZQUFZLENBQ2xDLENBQUE7UUFFRCxPQUFPLFlBQVksQ0FBQTtJQUNyQixDQUFDO0NBQ0Y7QUF4SkQsa0NBd0pDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IGJjcnlwdCBmcm9tICdiY3J5cHQnXG5pbXBvcnQgand0IGZyb20gJ2pzb253ZWJ0b2tlbidcbmltcG9ydCBVbmF1dGhvcml6ZWRFcnJvciBmcm9tICcuL2Vycm9ycy9VbmF1dGhvcml6ZWRFcnJvcidcbmltcG9ydCBGb3JiaWRkZW5FcnJvciBmcm9tICcuL2Vycm9ycy9Gb3JiaWRkZW5FcnJvcidcbmltcG9ydCBJbnZhbGlkUm9sZUVycm9yIGZyb20gJy4vZXJyb3JzL0ludmFsaWRSb2xlRXJyb3InXG5pbXBvcnQge1xuICBFYXN5SldUQXV0aE9wdGlvbnMsXG4gIFJlZ2lzdGVyUmV0dXJuVmFsdWUsXG4gIExvZ2luUmV0dXJuVmFsdWUsXG4gIFBhc3N3b3JkLFxuICBVc2VybmFtZSxcbiAgUm9sZSxcbiAgUm9sZXMsXG4gIEpzb25XZWJUb2tlbixcbiAgQXV0aFJldHVyblZhbHVlLFxuICBHZXRVc2VyRm9yVXNlcm5hbWVDYWxsYmFjayxcbiAgSnNvbldlYlRva2VuUGF5bG9hZFxufSBmcm9tICcuL3R5cGVzL0Vhc3lKV1RBdXRoJ1xuaW1wb3J0IHsgSUVhc3lKV1RBdXRoIH0gZnJvbSAnLi9pbnRlcmZhY2VzL0lFYXN5SldUQXV0aCdcblxuY29uc3QgZGVmYXVsdEdldFVzZXJGb3JVc2VybmFtZTogR2V0VXNlckZvclVzZXJuYW1lQ2FsbGJhY2sgPSAoKSA9PiB7XG4gIHRocm93IG5ldyBFcnJvcihgSUVhc3lKV1RBdXRoOjpvblJlcXVlc3RVc2VyRm9yVXNlcm5hbWUgaGFzIG5vdCBiZWVuIHNldC5gKVxufVxuXG5leHBvcnQgY2xhc3MgRWFzeUpXVEF1dGggaW1wbGVtZW50cyBJRWFzeUpXVEF1dGgge1xuICBvcHRpb25zOiBFYXN5SldUQXV0aE9wdGlvbnNcblxuICBwcm90ZWN0ZWQgZ2V0VXNlckZvclVzZXJuYW1lOiBHZXRVc2VyRm9yVXNlcm5hbWVDYWxsYmFjayA9IGRlZmF1bHRHZXRVc2VyRm9yVXNlcm5hbWVcbiAgcHJvdGVjdGVkIHRva2VuczogUmVjb3JkPEpzb25XZWJUb2tlbiwgSnNvbldlYlRva2VuPiA9IHt9IC8qIHJlZnJlc2hUb2tlbiAtPiBhY2Nlc3NUb2tlbiAqL1xuXG4gIGNvbnN0cnVjdG9yIChvcHRpb25zOiBFYXN5SldUQXV0aE9wdGlvbnMpIHtcbiAgICB0aGlzLm9wdGlvbnMgPSBvcHRpb25zXG4gIH1cblxuICBhc3luYyByZWdpc3Rlcih1c2VybmFtZTogVXNlcm5hbWUsIHBhc3N3b3JkOiBQYXNzd29yZCwgcm9sZT86IFJvbGUpOiBQcm9taXNlPFJlZ2lzdGVyUmV0dXJuVmFsdWU+IHtcbiAgICBjb25zdCBzYWx0Um91bmRzID0gdGhpcy5vcHRpb25zLnNhbHRSb3VuZHMgfHwgMTBcbiAgICBjb25zdCBoYXNoID0gYXdhaXQgYmNyeXB0Lmhhc2gocGFzc3dvcmQsIHNhbHRSb3VuZHMpXG5cbiAgICBjb25zdCBfcm9sZSA9IHJvbGUgfHwgdGhpcy5vcHRpb25zLnJvbGVzLmRlZmF1bHRcbiAgICBpZiAoIXRoaXMub3B0aW9ucy5yb2xlcy5hdmFpbGFibGUuaW5jbHVkZXMoX3JvbGUpKSB7XG4gICAgICB0aHJvdyBuZXcgSW52YWxpZFJvbGVFcnJvcigpXG4gICAgfVxuXG5cbiAgICBjb25zdCByZWZyZXNoVG9rZW4gPSB0aGlzLl9nZXRSZWZyZXNoVG9rZW4odXNlcm5hbWUsIF9yb2xlKVxuICAgIGNvbnN0IGFjY2Vzc1Rva2VuID0gdGhpcy5fZ2V0QWNjZXNzVG9rZW4odXNlcm5hbWUsIF9yb2xlKVxuXG4gICAgdGhpcy50b2tlbnNbcmVmcmVzaFRva2VuXSA9IGFjY2Vzc1Rva2VuXG5cbiAgICByZXR1cm4ge1xuICAgICAgdXNlckluZm86IHtcbiAgICAgICAgaGFzaCxcbiAgICAgICAgcm9sZTogX3JvbGVcbiAgICAgIH0sXG4gICAgICB0b2tlbnM6IHtcbiAgICAgICAgcmVmcmVzaDogcmVmcmVzaFRva2VuLFxuICAgICAgICBhY2Nlc3M6IGFjY2Vzc1Rva2VuXG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgYXN5bmMgbG9naW4odXNlcm5hbWU6IFVzZXJuYW1lLCBwYXNzd29yZDogUGFzc3dvcmQpOiBQcm9taXNlPExvZ2luUmV0dXJuVmFsdWU+IHtcbiAgICBjb25zdCB1c2VyID0gYXdhaXQgdGhpcy5nZXRVc2VyRm9yVXNlcm5hbWUodXNlcm5hbWUpXG5cbiAgICBjb25zdCBtYXRjaGVzID0gYXdhaXQgYmNyeXB0LmNvbXBhcmUocGFzc3dvcmQsIHVzZXIuaGFzaClcbiAgICBpZiAoIW1hdGNoZXMpIHtcbiAgICAgIHRocm93IG5ldyBVbmF1dGhvcml6ZWRFcnJvcigpXG4gICAgfVxuXG4gICAgY29uc3QgcmVmcmVzaFRva2VuID0gdGhpcy5fZ2V0UmVmcmVzaFRva2VuKHVzZXJuYW1lLCB1c2VyLnJvbGUpXG4gICAgY29uc3QgYWNjZXNzVG9rZW4gPSB0aGlzLl9nZXRBY2Nlc3NUb2tlbih1c2VybmFtZSwgdXNlci5yb2xlKVxuXG4gICAgdGhpcy50b2tlbnNbcmVmcmVzaFRva2VuXSA9IGFjY2Vzc1Rva2VuXG5cbiAgICByZXR1cm4ge1xuICAgICAgdG9rZW5zOiB7XG4gICAgICAgIHJlZnJlc2g6IHJlZnJlc2hUb2tlbixcbiAgICAgICAgYWNjZXNzOiBhY2Nlc3NUb2tlblxuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIGFzeW5jIHJlZnJlc2gocmVmcmVzaFRva2VuOiBKc29uV2ViVG9rZW4pOiBQcm9taXNlPExvZ2luUmV0dXJuVmFsdWU+IHtcbiAgICBjb25zdCBleGlzdGluZ0FjY2Vzc1Rva2VuID0gdGhpcy50b2tlbnNbcmVmcmVzaFRva2VuXVxuICAgIGlmICghZXhpc3RpbmdBY2Nlc3NUb2tlbikge1xuICAgICAgdGhyb3cgbmV3IEZvcmJpZGRlbkVycm9yKClcbiAgICB9XG5cbiAgICBjb25zdCBwYXlsb2FkOiBKc29uV2ViVG9rZW5QYXlsb2FkID0gand0LnZlcmlmeShyZWZyZXNoVG9rZW4sIHRoaXMub3B0aW9ucy5zZWNyZXRzLnJlZnJlc2hUb2tlbikgYXMgSnNvbldlYlRva2VuUGF5bG9hZFxuXG4gICAgY29uc3QgYWNjZXNzVG9rZW4gPSB0aGlzLl9nZXRBY2Nlc3NUb2tlbihwYXlsb2FkLnVzZXJuYW1lLCBwYXlsb2FkLnJvbGUpXG5cbiAgICB0aGlzLnRva2Vuc1tyZWZyZXNoVG9rZW5dID0gYWNjZXNzVG9rZW5cblxuICAgIHJldHVybiB7XG4gICAgICB0b2tlbnM6IHtcbiAgICAgICAgcmVmcmVzaDogcmVmcmVzaFRva2VuLFxuICAgICAgICBhY2Nlc3M6IGFjY2Vzc1Rva2VuXG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgbG9nb3V0KGFjY2Vzc1Rva2VuOiBKc29uV2ViVG9rZW4pOiB2b2lkIHtcbiAgICBjb25zdCBpdGVtID0gT2JqZWN0LmVudHJpZXModGhpcy50b2tlbnMpLmZpbmQoKFtfLCBhY2Nlc3NdKSA9PiB7XG4gICAgICByZXR1cm4gYWNjZXNzID09PSBhY2Nlc3NUb2tlblxuICAgIH0pXG5cbiAgICBpZiAoIWl0ZW0pIHtcbiAgICAgIHRocm93IG5ldyBGb3JiaWRkZW5FcnJvcigpXG4gICAgfVxuXG4gICAgY29uc3QgcmVmcmVzaFRva2VuID0gaXRlbVswXVxuXG4gICAgZGVsZXRlIHRoaXMudG9rZW5zW3JlZnJlc2hUb2tlbl1cbiAgfVxuXG4gIGFzeW5jIHZhbGlkYXRlKGFjY2Vzc1Rva2VuOiBKc29uV2ViVG9rZW4sIGFjY2VwdGVkUm9sZXM6IFJvbGVzID0gW10pOiBQcm9taXNlPEF1dGhSZXR1cm5WYWx1ZT4ge1xuICAgIGNvbnN0IGl0ZW0gPSBPYmplY3QuZW50cmllcyh0aGlzLnRva2VucykuZmluZCgoW18sIGFjY2Vzc10pID0+IHtcbiAgICAgIHJldHVybiBhY2Nlc3MgPT09IGFjY2Vzc1Rva2VuXG4gICAgfSlcblxuICAgIGlmICghaXRlbSkge1xuICAgICAgdGhyb3cgbmV3IEZvcmJpZGRlbkVycm9yKClcbiAgICB9XG5cbiAgICBjb25zdCBwYXlsb2FkOiBKc29uV2ViVG9rZW5QYXlsb2FkID0gand0LnZlcmlmeShhY2Nlc3NUb2tlbiwgdGhpcy5vcHRpb25zLnNlY3JldHMuYWNjZXNzVG9rZW4pIGFzIEpzb25XZWJUb2tlblBheWxvYWRcblxuICAgIGxldCBoYXNSb2xlID0gZmFsc2VcbiAgICBpZiAoYWNjZXB0ZWRSb2xlcy5sZW5ndGggPiAwKSB7XG4gICAgICBhY2NlcHRlZFJvbGVzLmZvckVhY2gocm9sZSA9PiB7XG4gICAgICAgIGlmIChyb2xlID09PSBwYXlsb2FkLnJvbGUpIHtcbiAgICAgICAgICBoYXNSb2xlID0gdHJ1ZVxuICAgICAgICB9XG4gICAgICB9KVxuICAgIH0gZWxzZSB7XG4gICAgICBoYXNSb2xlID0gdHJ1ZVxuICAgIH1cblxuICAgIGlmICghaGFzUm9sZSkge1xuICAgICAgdGhyb3cgbmV3IEZvcmJpZGRlbkVycm9yKClcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5nZXRVc2VyRm9yVXNlcm5hbWUocGF5bG9hZC51c2VybmFtZSlcbiAgfVxuXG4gIG9uUmVxdWVzdFVzZXJGb3JVc2VybmFtZShjYjogR2V0VXNlckZvclVzZXJuYW1lQ2FsbGJhY2spOiB2b2lkIHtcbiAgICB0aGlzLmdldFVzZXJGb3JVc2VybmFtZSA9IGNiXG4gIH1cblxuICBwcm90ZWN0ZWQgX2dldEFjY2Vzc1Rva2VuKHVzZXJuYW1lOiBVc2VybmFtZSwgcm9sZTogUm9sZSk6IHN0cmluZyB7XG4gICAgY29uc3QgZXhwaXJlc0luID0gdGhpcy5vcHRpb25zLmFjY2Vzc1Rva2VuRXhwaXJlc0luTWludXRlcyB8fCA5MFxuICAgIGNvbnN0IGFjY2Vzc1Rva2VuID0gand0LnNpZ24oXG4gICAgICB7XG4gICAgICAgIHVzZXJuYW1lLFxuICAgICAgICByb2xlXG4gICAgICB9LFxuICAgICAgdGhpcy5vcHRpb25zLnNlY3JldHMuYWNjZXNzVG9rZW4sXG4gICAgICB7XG4gICAgICAgIGV4cGlyZXNJbjogYCR7ZXhwaXJlc0lufW1gXG4gICAgICB9XG4gICAgKVxuXG4gICAgcmV0dXJuIGFjY2Vzc1Rva2VuXG4gIH1cblxuICBwcm90ZWN0ZWQgX2dldFJlZnJlc2hUb2tlbih1c2VybmFtZTogVXNlcm5hbWUsIHJvbGU6IFJvbGUpOiBzdHJpbmcge1xuICAgIGNvbnN0IHJlZnJlc2hUb2tlbiA9IGp3dC5zaWduKFxuICAgICAge1xuICAgICAgICB1c2VybmFtZSxcbiAgICAgICAgcm9sZVxuICAgICAgfSxcbiAgICAgIHRoaXMub3B0aW9ucy5zZWNyZXRzLnJlZnJlc2hUb2tlblxuICAgIClcblxuICAgIHJldHVybiByZWZyZXNoVG9rZW5cbiAgfVxufVxuIl19