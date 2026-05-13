import { api } from '@/lib/api'
import type {
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  RegisterResponse,
  ResendVerificationRequest,
  TwoFactorConfirmRequest,
  TwoFactorDisableRequest,
  TwoFactorVerifyRequest,
  UserDto,
  VerifyEmailRequest,
} from '@/types'

export const authService = {
  register(body: RegisterRequest) {
    return api.post<RegisterResponse>('/auth/register', body).then((r) => r.data)
  },

  verifyEmail(body: VerifyEmailRequest) {
    return api.post<void>('/auth/verify-email', body).then((r) => r.data)
  },

  resendVerification(body: ResendVerificationRequest) {
    return api.post<void>('/auth/resend-verification', body).then((r) => r.data)
  },

  login(body: LoginRequest) {
    return api.post<LoginResponse>('/auth/login', body).then((r) => r.data)
  },

  twoFactorVerify(body: TwoFactorVerifyRequest) {
    return api.post<void>('/auth/2fa/verify', body).then((r) => r.data)
  },

  twoFactorEnable() {
    return api.post<void>('/auth/2fa/enable').then((r) => r.data)
  },

  twoFactorConfirm(body: TwoFactorConfirmRequest) {
    return api.post<void>('/auth/2fa/confirm', body).then((r) => r.data)
  },

  twoFactorDisable(body: TwoFactorDisableRequest) {
    return api.post<void>('/auth/2fa/disable', body).then((r) => r.data)
  },

  logout() {
    return api.post<void>('/auth/logout').then((r) => r.data)
  },

  me() {
    return api.get<UserDto>('/me').then((r) => r.data)
  },

  googleOAuthUrl: '/oauth2/authorization/google',
}
