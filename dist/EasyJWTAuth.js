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
const DuplicateUserError_1 = __importDefault(require("./errors/DuplicateUserError"));
const InvalidRoleError_1 = __importDefault(require("./errors/InvalidRoleError"));
const defaultGetUserForUsername = () => {
    throw new Error(`IEasyJWTAuth::onRequestUserForUsername has not been set.`);
};
class EasyJWTAuth {
    constructor(options) {
        this._getUserForUsername = defaultGetUserForUsername;
        this._tokens = {}; /* refreshToken -> accessToken */
        this._passwordResetTokens = {};
        this.options = options;
    }
    async register(username, password, role) {
        let existingUser;
        try {
            existingUser = await this._getUserForUsername(username);
        }
        catch (_) {
            // no-opt
        }
        if (existingUser) {
            throw new DuplicateUserError_1.default();
        }
        const hash = await this._getHash(password);
        const _role = role || this.options.roles.default;
        if (!this.options.roles.available.includes(_role)) {
            throw new InvalidRoleError_1.default();
        }
        const refreshToken = this._getRefreshToken(username, _role);
        const accessToken = this._getAccessToken(username, _role);
        this._tokens[refreshToken] = accessToken;
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
        const user = await this._getUserForUsername(username);
        const matches = await bcrypt_1.default.compare(password, user.hash);
        if (!matches) {
            throw new UnauthorizedError_1.default();
        }
        const refreshToken = this._getRefreshToken(username, user.role);
        const accessToken = this._getAccessToken(username, user.role);
        this._tokens[refreshToken] = accessToken;
        return {
            tokens: {
                refresh: refreshToken,
                access: accessToken
            },
            user
        };
    }
    async refresh(refreshToken) {
        const existingAccessToken = this._tokens[refreshToken];
        if (!existingAccessToken) {
            throw new ForbiddenError_1.default();
        }
        const payload = jsonwebtoken_1.default.verify(refreshToken, this.options.secrets.refreshToken);
        const accessToken = this._getAccessToken(payload.username, payload.role);
        this._tokens[refreshToken] = accessToken;
        return {
            tokens: {
                refresh: refreshToken,
                access: accessToken
            }
        };
    }
    logout(accessToken) {
        const item = Object.entries(this._tokens).find(([_, access]) => {
            return access === accessToken;
        });
        if (!item) {
            throw new ForbiddenError_1.default();
        }
        const refreshToken = item[0];
        delete this._tokens[refreshToken];
    }
    async forgotPassword(username) {
        const user = await this._getUserForUsername(username);
        const resetToken = this._getPasswordResetToken();
        this._passwordResetTokens[username] = resetToken;
        return {
            user,
            tokens: {
                passwordReset: resetToken
            }
        };
    }
    async forgotPasswordUpdate(username, newPassword, passwordResetToken) {
        const token = this._passwordResetTokens[username];
        if (!token) {
            throw new ForbiddenError_1.default();
        }
        if (token !== passwordResetToken) {
            throw new UnauthorizedError_1.default();
        }
        jsonwebtoken_1.default.verify(token, this.options.secrets.passwordResetToken);
        const user = await this._getUserForUsername(username);
        user.hash = await this._getHash(newPassword);
        delete this._passwordResetTokens[username];
        return {
            user
        };
    }
    async validate(accessToken, acceptedRoles = []) {
        let _accessToken = accessToken;
        if (_accessToken && _accessToken.includes(' ')) {
            const splitToken = _accessToken.split(' ');
            _accessToken = splitToken[1];
        }
        const item = Object.entries(this._tokens).find(([_, access]) => {
            return access === _accessToken;
        });
        if (!item) {
            throw new ForbiddenError_1.default();
        }
        const payload = jsonwebtoken_1.default.verify(_accessToken, this.options.secrets.accessToken);
        let hasRole = false;
        if (acceptedRoles.length > 0) {
            acceptedRoles.forEach((role) => {
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
        const user = await this._getUserForUsername(payload.username);
        return {
            user,
            tokens: {
                access: item[1],
                refresh: item[0]
            }
        };
    }
    onRequestUserForUsername(cb) {
        this._getUserForUsername = cb;
    }
    _getAccessToken(username, role) {
        const expiresIn = this.options.accessTokenExpiresInMinutes || 90;
        const accessToken = jsonwebtoken_1.default.sign({
            username,
            role
        }, this.options.secrets.accessToken, {
            expiresIn: expiresIn * 60 // convert minutes to seconds
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
    _getPasswordResetToken() {
        const expiresIn = this.options.passwordResetTokenExpiresInMinutes || 10;
        const passwordResetToken = jsonwebtoken_1.default.sign({}, this.options.secrets.passwordResetToken, {
            expiresIn: expiresIn * 60 // convert minutes to seconds
        });
        return passwordResetToken;
    }
    async _getHash(password) {
        const saltRounds = this.options.saltRounds || 10;
        const hash = await bcrypt_1.default.hash(password, saltRounds);
        return hash;
    }
}
exports.EasyJWTAuth = EasyJWTAuth;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiRWFzeUpXVEF1dGguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvRWFzeUpXVEF1dGgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7O0FBQUEsb0RBQTJCO0FBQzNCLGdFQUE4QjtBQUM5QixtRkFBMEQ7QUFDMUQsNkVBQW9EO0FBQ3BELHFGQUE0RDtBQUM1RCxpRkFBd0Q7QUFvQnhELE1BQU0seUJBQXlCLEdBQStCLEdBQUcsRUFBRTtJQUNqRSxNQUFNLElBQUksS0FBSyxDQUFDLDBEQUEwRCxDQUFDLENBQUE7QUFDN0UsQ0FBQyxDQUFBO0FBRUQsTUFBYSxXQUFXO0lBVXRCLFlBQVksT0FBMkI7UUFQN0Isd0JBQW1CLEdBQStCLHlCQUF5QixDQUFBO1FBQzNFLFlBQU8sR0FHYixFQUFFLENBQUEsQ0FBQyxpQ0FBaUM7UUFDOUIseUJBQW9CLEdBQW1DLEVBQUUsQ0FBQTtRQUdqRSxJQUFJLENBQUMsT0FBTyxHQUFHLE9BQU8sQ0FBQTtJQUN4QixDQUFDO0lBRUQsS0FBSyxDQUFDLFFBQVEsQ0FDWixRQUFrQixFQUNsQixRQUFrQixFQUNsQixJQUFXO1FBRVgsSUFBSSxZQUFZLENBQUE7UUFDaEIsSUFBSTtZQUNGLFlBQVksR0FBRyxNQUFNLElBQUksQ0FBQyxtQkFBbUIsQ0FBQyxRQUFRLENBQUMsQ0FBQTtTQUN4RDtRQUFDLE9BQU8sQ0FBQyxFQUFFO1lBQ1YsU0FBUztTQUNWO1FBQ0QsSUFBSSxZQUFZLEVBQUU7WUFDaEIsTUFBTSxJQUFJLDRCQUFrQixFQUFFLENBQUE7U0FDL0I7UUFFRCxNQUFNLElBQUksR0FBRyxNQUFNLElBQUksQ0FBQyxRQUFRLENBQUMsUUFBUSxDQUFDLENBQUE7UUFFMUMsTUFBTSxLQUFLLEdBQUcsSUFBSSxJQUFJLElBQUksQ0FBQyxPQUFPLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQTtRQUNoRCxJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxLQUFLLENBQUMsU0FBUyxDQUFDLFFBQVEs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QkFBa0IsQ0FBQTtJQUMzQixDQUFDO0lBRVMsS0FBSyxDQUFDLFFBQVEsQ0FBQyxRQUFrQjtRQUN6QyxNQUFNLFVBQVUsR0FBRyxJQUFJLENBQUMsT0FBTyxDQUFDLFVBQVUsSUFBSSxFQUFFLENBQUE7UUFDaEQsTUFBTSxJQUFJLEdBQUcsTUFBTSxnQkFBTSxDQUFDLElBQUksQ0FBQyxRQUFRLEVBQUUsVUFBVSxDQUFDLENBQUE7UUFDcEQsT0FBTyxJQUFJLENBQUE7SUFDYixDQUFDO0NBQ0Y7QUE1UEQsa0NBNFBDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IGJjcnlwdCBmcm9tICdiY3J5cHQnXG5pbXBvcnQgand0IGZyb20gJ2pzb253ZWJ0b2tlbidcbmltcG9ydCBVbmF1dGhvcml6ZWRFcnJvciBmcm9tICcuL2Vycm9ycy9VbmF1dGhvcml6ZWRFcnJvcidcbmltcG9ydCBGb3JiaWRkZW5FcnJvciBmcm9tICcuL2Vycm9ycy9Gb3JiaWRkZW5FcnJvcidcbmltcG9ydCBEdXBsaWNhdGVVc2VyRXJyb3IgZnJvbSAnLi9lcnJvcnMvRHVwbGljYXRlVXNlckVycm9yJ1xuaW1wb3J0IEludmFsaWRSb2xlRXJyb3IgZnJvbSAnLi9lcnJvcnMvSW52YWxpZFJvbGVFcnJvcidcbmltcG9ydCB7XG4gIEVhc3lKV1RBdXRoT3B0aW9ucyxcbiAgUmVnaXN0ZXJSZXR1cm5WYWx1ZSxcbiAgTG9naW5SZXR1cm5WYWx1ZSxcbiAgUmVmcmVzaFJldHVyblZhbHVlLFxuICBGb3Jnb3RQYXNzd29yZFJldHVyblZhbHVlLFxuICBGb3Jnb3RQYXNzd29yZFVwZGF0ZVJldHVyblZhbHVlLFxuICBQYXNzd29yZCxcbiAgUGFzc3dvcmRIYXNoLFxuICBVc2VybmFtZSxcbiAgUm9sZSxcbiAgUm9sZXMsXG4gIEpzb25XZWJUb2tlbixcbiAgQXV0aFJldHVyblZhbHVlLFxuICBHZXRVc2VyRm9yVXNlcm5hbWVDYWxsYmFjayxcbiAgSnNvbldlYlRva2VuUGF5bG9hZFxufSBmcm9tICcuL3R5cGVzL0Vhc3lKV1RBdXRoJ1xuaW1wb3J0IHsgSUVhc3lKV1RBdXRoIH0gZnJvbSAnLi9pbnRlcmZhY2VzL0lFYXN5SldUQXV0aCdcblxuY29uc3QgZGVmYXVsdEdldFVzZXJGb3JVc2VybmFtZTogR2V0VXNlckZvclVzZXJuYW1lQ2FsbGJhY2sgPSAoKSA9PiB7XG4gIHRocm93IG5ldyBFcnJvcihgSUVhc3lKV1RBdXRoOjpvblJlcXVlc3RVc2VyRm9yVXNlcm5hbWUgaGFzIG5vdCBiZWVuIHNldC5gKVxufVxuXG5leHBvcnQgY2xhc3MgRWFzeUpXVEF1dGggaW1wbGVtZW50cyBJRWFzeUpXVEF1dGgge1xuICBvcHRpb25zOiBFYXN5SldUQXV0aE9wdGlvbnNcblxuICBwcm90ZWN0ZWQgX2dldFVzZXJGb3JVc2VybmFtZTogR2V0VXNlckZvclVzZXJuYW1lQ2FsbGJhY2sgPSBkZWZhdWx0R2V0VXNlckZvclVzZXJuYW1lXG4gIHByb3RlY3RlZCBfdG9rZW5zOiBSZWNvcmQ8XG4gICAgSnNvbldlYlRva2VuLFxuICAgIEpzb25XZWJUb2tlblxuICA+ID0ge30gLyogcmVmcmVzaFRva2VuIC0+IGFjY2Vzc1Rva2VuICovXG4gIHByb3RlY3RlZCBfcGFzc3dvcmRSZXNldFRva2VuczogUmVjb3JkPFVzZXJuYW1lLCBKc29uV2ViVG9rZW4+ID0ge31cblxuICBjb25zdHJ1Y3RvcihvcHRpb25zOiBFYXN5SldUQXV0aE9wdGlvbnMpIHtcbiAgICB0aGlzLm9wdGlvbnMgPSBvcHRpb25zXG4gIH1cblxuICBhc3luYyByZWdpc3RlcihcbiAgICB1c2VybmFtZTogVXNlcm5hbWUsXG4gICAgcGFzc3dvcmQ6IFBhc3N3b3JkLFxuICAgIHJvbGU/OiBSb2xlXG4gICk6IFByb21pc2U8UmVnaXN0ZXJSZXR1cm5WYWx1ZT4ge1xuICAgIGxldCBleGlzdGluZ1VzZXJcbiAgICB0cnkge1xuICAgICAgZXhpc3RpbmdVc2VyID0gYXdhaXQgdGhpcy5fZ2V0VXNlckZvclVzZXJuYW1lKHVzZXJuYW1lKVxuICAgIH0gY2F0Y2ggKF8pIHtcbiAgICAgIC8vIG5vLW9wdFxuICAgIH1cbiAgICBpZiAoZXhpc3RpbmdVc2VyKSB7XG4gICAgICB0aHJvdyBuZXcgRHVwbGljYXRlVXNlckVycm9yKClcbiAgICB9XG5cbiAgICBjb25zdCBoYXNoID0gYXdhaXQgdGhpcy5fZ2V0SGFzaChwYXNzd29yZClcblxuICAgIGNvbnN0IF9yb2xlID0gcm9sZSB8fCB0aGlzLm9wdGlvbnMucm9sZXMuZGVmYXVsdFxuICAgIGlmICghdGhpcy5vcHRpb25zLnJvbGVzLmF2YWlsYWJsZS5pbmNsdWRlcyhfcm9sZSkpIHtcbiAgICAgIHRocm93IG5ldyBJbnZhbGlkUm9sZUVycm9yKClcbiAgICB9XG5cbiAgICBjb25zdCByZWZyZXNoVG9rZW4gPSB0aGlzLl9nZXRSZWZyZXNoVG9rZW4odXNlcm5hbWUsIF9yb2xlKVxuICAgIGNvbnN0IGFjY2Vzc1Rva2VuID0gdGhpcy5fZ2V0QWNjZXNzVG9rZW4odXNlcm5hbWUsIF9yb2xlKVxuXG4gICAgdGhpcy5fdG9rZW5zW3JlZnJlc2hUb2tlbl0gPSBhY2Nlc3NUb2tlblxuXG4gICAgcmV0dXJuIHtcbiAgICAgIHVzZXJJbmZvOiB7XG4gICAgICAgIGhhc2gsXG4gICAgICAgIHJvbGU6IF9yb2xlXG4gICAgICB9LFxuICAgICAgdG9rZW5zOiB7XG4gICAgICAgIHJlZnJlc2g6IHJlZnJlc2hUb2tlbixcbiAgICAgICAgYWNjZXNzOiBhY2Nlc3NUb2tlblxuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIGFzeW5jIGxvZ2luKFxuICAgIHVzZXJuYW1lOiBVc2VybmFtZSxcbiAgICBwYXNzd29yZDogUGFzc3dvcmRcbiAgKTogUHJvbWlzZTxMb2dpblJldHVyblZhbHVlPiB7XG4gICAgY29uc3QgdXNlciA9IGF3YWl0IHRoaXMuX2dldFVzZXJGb3JVc2VybmFtZSh1c2VybmFtZSlcblxuICAgIGNvbnN0IG1hdGNoZXMgPSBhd2FpdCBiY3J5cHQuY29tcGFyZShwYXNzd29yZCwgdXNlci5oYXNoKVxuICAgIGlmICghbWF0Y2hlcykge1xuICAgICAgdGhyb3cgbmV3IFVuYXV0aG9yaXplZEVycm9yKClcbiAgICB9XG5cbiAgICBjb25zdCByZWZyZXNoVG9rZW4gPSB0aGlzLl9nZXRSZWZyZXNoVG9rZW4odXNlcm5hbWUsIHVzZXIucm9sZSlcbiAgICBjb25zdCBhY2Nlc3NUb2tlbiA9IHRoaXMuX2dldEFjY2Vzc1Rva2VuKHVzZXJuYW1lLCB1c2VyLnJvbGUpXG5cbiAgICB0aGlzLl90b2tlbnNbcmVmcmVzaFRva2VuXSA9IGFjY2Vzc1Rva2VuXG5cbiAgICByZXR1cm4ge1xuICAgICAgdG9rZW5zOiB7XG4gICAgICAgIHJlZnJlc2g6IHJlZnJlc2hUb2tlbixcbiAgICAgICAgYWNjZXNzOiBhY2Nlc3NUb2tlblxuICAgICAgfSxcbiAgICAgIHVzZXJcbiAgICB9XG4gIH1cblxuICBhc3luYyByZWZyZXNoKHJlZnJlc2hUb2tlbjogSnNvbldlYlRva2VuKTogUHJvbWlzZTxSZWZyZXNoUmV0dXJuVmFsdWU+IHtcbiAgICBjb25zdCBleGlzdGluZ0FjY2Vzc1Rva2VuID0gdGhpcy5fdG9rZW5zW3JlZnJlc2hUb2tlbl1cbiAgICBpZiAoIWV4aXN0aW5nQWNjZXNzVG9rZW4pIHtcbiAgICAgIHRocm93IG5ldyBGb3JiaWRkZW5FcnJvcigpXG4gICAgfVxuXG4gICAgY29uc3QgcGF5bG9hZDogSnNvbldlYlRva2VuUGF5bG9hZCA9IGp3dC52ZXJpZnkoXG4gICAgICByZWZyZXNoVG9rZW4sXG4gICAgICB0aGlzLm9wdGlvbnMuc2VjcmV0cy5yZWZyZXNoVG9rZW5cbiAgICApIGFzIEpzb25XZWJUb2tlblBheWxvYWRcblxuICAgIGNvbnN0IGFjY2Vzc1Rva2VuID0gdGhpcy5fZ2V0QWNjZXNzVG9rZW4ocGF5bG9hZC51c2VybmFtZSwgcGF5bG9hZC5yb2xlKVxuXG4gICAgdGhpcy5fdG9rZW5zW3JlZnJlc2hUb2tlbl0gPSBhY2Nlc3NUb2tlblxuXG4gICAgcmV0dXJuIHtcbiAgICAgIHRva2Vuczoge1xuICAgICAgICByZWZyZXNoOiByZWZyZXNoVG9rZW4sXG4gICAgICAgIGFjY2VzczogYWNjZXNzVG9rZW5cbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICBsb2dvdXQoYWNjZXNzVG9rZW46IEpzb25XZWJUb2tlbik6IHZvaWQge1xuICAgIGNvbnN0IGl0ZW0gPSBPYmplY3QuZW50cmllcyh0aGlzLl90b2tlbnMpLmZpbmQoKFtfLCBhY2Nlc3NdKSA9PiB7XG4gICAgICByZXR1cm4gYWNjZXNzID09PSBhY2Nlc3NUb2tlblxuICAgIH0pXG5cbiAgICBpZiAoIWl0ZW0pIHtcbiAgICAgIHRocm93IG5ldyBGb3JiaWRkZW5FcnJvcigpXG4gICAgfVxuXG4gICAgY29uc3QgcmVmcmVzaFRva2VuID0gaXRlbVswXVxuXG4gICAgZGVsZXRlIHRoaXMuX3Rva2Vuc1tyZWZyZXNoVG9rZW5dXG4gIH1cblxuICBhc3luYyBmb3Jnb3RQYXNzd29yZCh1c2VybmFtZTogVXNlcm5hbWUpOiBQcm9taXNlPEZvcmdvdFBhc3N3b3JkUmV0dXJuVmFsdWU+IHtcbiAgICBjb25zdCB1c2VyID0gYXdhaXQgdGhpcy5fZ2V0VXNlckZvclVzZXJuYW1lKHVzZXJuYW1lKVxuICAgIGNvbnN0IHJlc2V0VG9rZW4gPSB0aGlzLl9nZXRQYXNzd29yZFJlc2V0VG9rZW4oKVxuICAgIHRoaXMuX3Bhc3N3b3JkUmVzZXRUb2tlbnNbdXNlcm5hbWVdID0gcmVzZXRUb2tlblxuXG4gICAgcmV0dXJuIHtcbiAgICAgIHVzZXIsXG4gICAgICB0b2tlbnM6IHtcbiAgICAgICAgcGFzc3dvcmRSZXNldDogcmVzZXRUb2tlblxuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIGFzeW5jIGZvcmdvdFBhc3N3b3JkVXBkYXRlKFxuICAgIHVzZXJuYW1lOiBVc2VybmFtZSxcbiAgICBuZXdQYXNzd29yZDogUGFzc3dvcmQsXG4gICAgcGFzc3dvcmRSZXNldFRva2VuOiBKc29uV2ViVG9rZW5cbiAgKTogUHJvbWlzZTxGb3Jnb3RQYXNzd29yZFVwZGF0ZVJldHVyblZhbHVlPiB7XG4gICAgY29uc3QgdG9rZW4gPSB0aGlzLl9wYXNzd29yZFJlc2V0VG9rZW5zW3VzZXJuYW1lXVxuICAgIGlmICghdG9rZW4pIHtcbiAgICAgIHRocm93IG5ldyBGb3JiaWRkZW5FcnJvcigpXG4gICAgfVxuXG4gICAgaWYgKHRva2VuICE9PSBwYXNzd29yZFJlc2V0VG9rZW4pIHtcbiAgICAgIHRocm93IG5ldyBVbmF1dGhvcml6ZWRFcnJvcigpXG4gICAgfVxuXG4gICAgand0LnZlcmlmeSh0b2tlbiwgdGhpcy5vcHRpb25zLnNlY3JldHMucGFzc3dvcmRSZXNldFRva2VuKVxuXG4gICAgY29uc3QgdXNlciA9IGF3YWl0IHRoaXMuX2dldFVzZXJGb3JVc2VybmFtZSh1c2VybmFtZSlcbiAgICB1c2VyLmhhc2ggPSBhd2FpdCB0aGlzLl9nZXRIYXNoKG5ld1Bhc3N3b3JkKVxuXG4gICAgZGVsZXRlIHRoaXMuX3Bhc3N3b3JkUmVzZXRUb2tlbnNbdXNlcm5hbWVdXG5cbiAgICByZXR1cm4ge1xuICAgICAgdXNlclxuICAgIH1cbiAgfVxuXG4gIGFzeW5jIHZhbGlkYXRlKFxuICAgIGFjY2Vzc1Rva2VuOiBKc29uV2ViVG9rZW4sXG4gICAgYWNjZXB0ZWRSb2xlczogUm9sZXMgPSBbXVxuICApOiBQcm9taXNlPEF1dGhSZXR1cm5WYWx1ZT4ge1xuICAgIGxldCBfYWNjZXNzVG9rZW4gPSBhY2Nlc3NUb2tlblxuICAgIGlmIChfYWNjZXNzVG9rZW4gJiYgX2FjY2Vzc1Rva2VuLmluY2x1ZGVzKCcgJykpIHtcbiAgICAgIGNvbnN0IHNwbGl0VG9rZW4gPSBfYWNjZXNzVG9rZW4uc3BsaXQoJyAnKVxuICAgICAgX2FjY2Vzc1Rva2VuID0gc3BsaXRUb2tlblsxXVxuICAgIH1cblxuICAgIGNvbnN0IGl0ZW0gPSBPYmplY3QuZW50cmllcyh0aGlzLl90b2tlbnMpLmZpbmQoKFtfLCBhY2Nlc3NdKSA9PiB7XG4gICAgICByZXR1cm4gYWNjZXNzID09PSBfYWNjZXNzVG9rZW5cbiAgICB9KVxuXG4gICAgaWYgKCFpdGVtKSB7XG4gICAgICB0aHJvdyBuZXcgRm9yYmlkZGVuRXJyb3IoKVxuICAgIH1cblxuICAgIGNvbnN0IHBheWxvYWQ6IEpzb25XZWJUb2tlblBheWxvYWQgPSBqd3QudmVyaWZ5KFxuICAgICAgX2FjY2Vzc1Rva2VuLFxuICAgICAgdGhpcy5vcHRpb25zLnNlY3JldHMuYWNjZXNzVG9rZW5cbiAgICApIGFzIEpzb25XZWJUb2tlblBheWxvYWRcblxuICAgIGxldCBoYXNSb2xlID0gZmFsc2VcbiAgICBpZiAoYWNjZXB0ZWRSb2xlcy5sZW5ndGggPiAwKSB7XG4gICAgICBhY2NlcHRlZFJvbGVzLmZvckVhY2goKHJvbGUpID0+IHtcbiAgICAgICAgaWYgKHJvbGUgPT09IHBheWxvYWQucm9sZSkge1xuICAgICAgICAgIGhhc1JvbGUgPSB0cnVlXG4gICAgICAgIH1cbiAgICAgIH0pXG4gICAgfSBlbHNlIHtcbiAgICAgIGhhc1JvbGUgPSB0cnVlXG4gICAgfVxuXG4gICAgaWYgKCFoYXNSb2xlKSB7XG4gICAgICB0aHJvdyBuZXcgRm9yYmlkZGVuRXJyb3IoKVxuICAgIH1cblxuICAgIGNvbnN0IHVzZXIgPSBhd2FpdCB0aGlzLl9nZXRVc2VyRm9yVXNlcm5hbWUocGF5bG9hZC51c2VybmFtZSlcbiAgICByZXR1cm4ge1xuICAgICAgdXNlcixcbiAgICAgIHRva2Vuczoge1xuICAgICAgICBhY2Nlc3M6IGl0ZW1bMV0sXG4gICAgICAgIHJlZnJlc2g6IGl0ZW1bMF1cbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICBvblJlcXVlc3RVc2VyRm9yVXNlcm5hbWUoY2I6IEdldFVzZXJGb3JVc2VybmFtZUNhbGxiYWNrKTogdm9pZCB7XG4gICAgdGhpcy5fZ2V0VXNlckZvclVzZXJuYW1lID0gY2JcbiAgfVxuXG4gIHByb3RlY3RlZCBfZ2V0QWNjZXNzVG9rZW4odXNlcm5hbWU6IFVzZXJuYW1lLCByb2xlOiBSb2xlKTogc3RyaW5nIHtcbiAgICBjb25zdCBleHBpcmVzSW4gPSB0aGlzLm9wdGlvbnMuYWNjZXNzVG9rZW5FeHBpcmVzSW5NaW51dGVzIHx8IDkwXG4gICAgY29uc3QgYWNjZXNzVG9rZW4gPSBqd3Quc2lnbihcbiAgICAgIHtcbiAgICAgICAgdXNlcm5hbWUsXG4gICAgICAgIHJvbGVcbiAgICAgIH0sXG4gICAgICB0aGlzLm9wdGlvbnMuc2VjcmV0cy5hY2Nlc3NUb2tlbixcbiAgICAgIHtcbiAgICAgICAgZXhwaXJlc0luOiBleHBpcmVzSW4gKiA2MCAvLyBjb252ZXJ0IG1pbnV0ZXMgdG8gc2Vjb25kc1xuICAgICAgfVxuICAgIClcblxuICAgIHJldHVybiBhY2Nlc3NUb2tlblxuICB9XG5cbiAgcHJvdGVjdGVkIF9nZXRSZWZyZXNoVG9rZW4odXNlcm5hbWU6IFVzZXJuYW1lLCByb2xlOiBSb2xlKTogc3RyaW5nIHtcbiAgICBjb25zdCByZWZyZXNoVG9rZW4gPSBqd3Quc2lnbihcbiAgICAgIHtcbiAgICAgICAgdXNlcm5hbWUsXG4gICAgICAgIHJvbGVcbiAgICAgIH0sXG4gICAgICB0aGlzLm9wdGlvbnMuc2VjcmV0cy5yZWZyZXNoVG9rZW5cbiAgICApXG5cbiAgICByZXR1cm4gcmVmcmVzaFRva2VuXG4gIH1cblxuICBwcm90ZWN0ZWQgX2dldFBhc3N3b3JkUmVzZXRUb2tlbigpOiBzdHJpbmcge1xuICAgIGNvbnN0IGV4cGlyZXNJbiA9IHRoaXMub3B0aW9ucy5wYXNzd29yZFJlc2V0VG9rZW5FeHBpcmVzSW5NaW51dGVzIHx8IDEwXG4gICAgY29uc3QgcGFzc3dvcmRSZXNldFRva2VuID0gand0LnNpZ24oXG4gICAgICB7fSxcbiAgICAgIHRoaXMub3B0aW9ucy5zZWNyZXRzLnBhc3N3b3JkUmVzZXRUb2tlbixcbiAgICAgIHtcbiAgICAgICAgZXhwaXJlc0luOiBleHBpcmVzSW4gKiA2MCAvLyBjb252ZXJ0IG1pbnV0ZXMgdG8gc2Vjb25kc1xuICAgICAgfVxuICAgIClcblxuICAgIHJldHVybiBwYXNzd29yZFJlc2V0VG9rZW5cbiAgfVxuXG4gIHByb3RlY3RlZCBhc3luYyBfZ2V0SGFzaChwYXNzd29yZDogUGFzc3dvcmQpOiBQcm9taXNlPFBhc3N3b3JkSGFzaD4ge1xuICAgIGNvbnN0IHNhbHRSb3VuZHMgPSB0aGlzLm9wdGlvbnMuc2FsdFJvdW5kcyB8fCAxMFxuICAgIGNvbnN0IGhhc2ggPSBhd2FpdCBiY3J5cHQuaGFzaChwYXNzd29yZCwgc2FsdFJvdW5kcylcbiAgICByZXR1cm4gaGFzaFxuICB9XG59XG4iXX0=